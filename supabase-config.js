// ============================================================
// SUPABASE CONFIGURATION — Abramov Elite Tool
// ============================================================
// Server sync configuration for EliteTool-Backend
// ============================================================

const SUPABASE_CONFIG = {
    url: 'https://mjllnxubsotqaanbxgvl.supabase.co',
    anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1qbGxueHVic290cWFhbmJ4Z3ZsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE5NTM5NTUsImV4cCI6MjA4NzUyOTk1NX0.VPe5unUzUviUCjiBVhPYHq78BlnBCZq12ZQXDI2QR0c',
    tables: {
        accessLogs: 'access_logs',
        securityEvents: 'security_events',
        siteConfig: 'site_config',
        blockedDevices: 'blocked_devices',
        activeSessions: 'active_sessions'
    }
};

// Supabase REST API helper
const SupabaseClient = {
    _headers() {
        return {
            'apikey': SUPABASE_CONFIG.anonKey,
            'Authorization': 'Bearer ' + SUPABASE_CONFIG.anonKey,
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        };
    },

    async insert(table, data) {
        try {
            const resp = await fetch(SUPABASE_CONFIG.url + '/rest/v1/' + table, {
                method: 'POST',
                headers: this._headers(),
                body: JSON.stringify(data)
            });
            return await resp.json();
        } catch (e) {
            console.warn('Supabase insert error:', e);
            return null;
        }
    },

    async select(table, query = '') {
        try {
            const resp = await fetch(SUPABASE_CONFIG.url + '/rest/v1/' + table + '?select=*' + (query ? '&' + query : ''), {
                headers: this._headers()
            });
            return await resp.json();
        } catch (e) {
            console.warn('Supabase select error:', e);
            return [];
        }
    },

    async update(table, match, data) {
        try {
            const resp = await fetch(SUPABASE_CONFIG.url + '/rest/v1/' + table + '?' + match, {
                method: 'PATCH',
                headers: this._headers(),
                body: JSON.stringify(data)
            });
            return await resp.json();
        } catch (e) {
            console.warn('Supabase update error:', e);
            return null;
        }
    },

    async delete(table, match) {
        try {
            const resp = await fetch(SUPABASE_CONFIG.url + '/rest/v1/' + table + '?' + match, {
                method: 'DELETE',
                headers: this._headers()
            });
            return resp.ok;
        } catch (e) {
            console.warn('Supabase delete error:', e);
            return false;
        }
    },

    async upsert(table, data) {
        try {
            const headers = this._headers();
            headers['Prefer'] = 'resolution=merge-duplicates,return=representation';
            const resp = await fetch(SUPABASE_CONFIG.url + '/rest/v1/' + table, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(data)
            });
            return await resp.json();
        } catch (e) {
            console.warn('Supabase upsert error:', e);
            return null;
        }
    },

    // Log a page access
    async logAccess(pageVisited) {
        const fp = await this.getDeviceFingerprint();
        return this.insert(SUPABASE_CONFIG.tables.accessLogs, {
            ip_address: await this.getIP(),
            user_agent: navigator.userAgent,
            device_fingerprint: fp,
            page_visited: pageVisited
        });
    },

    // Log a security event
    async logSecurityEvent(eventType, details = {}) {
        const fp = await this.getDeviceFingerprint();
        return this.insert(SUPABASE_CONFIG.tables.securityEvents, {
            event_type: eventType,
            device_fingerprint: fp,
            ip_address: await this.getIP(),
            details: details
        });
    },

    // Get public IP
    async getIP() {
        try {
            const resp = await fetch('https://api.ipify.org?format=json');
            const data = await resp.json();
            return data.ip;
        } catch (e) {
            return 'unknown';
        }
    },

    // Get device fingerprint (canvas + navigator hash)
    async getDeviceFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('fingerprint', 2, 2);
        const canvasData = canvas.toDataURL();

        const raw = canvasData + navigator.userAgent + navigator.language +
            screen.width + 'x' + screen.height + screen.colorDepth +
            new Date().getTimezoneOffset() + navigator.hardwareConcurrency;

        const encoder = new TextEncoder();
        const data = encoder.encode(raw);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // Check if device is blocked (server-side)
    async isDeviceBlocked() {
        try {
            const fp = await this.getDeviceFingerprint();
            const results = await this.select(SUPABASE_CONFIG.tables.blockedDevices,
                'device_fingerprint=eq.' + fp);
            if (results && results.length > 0) {
                const block = results[0];
                if (block.block_type === 'permanent') return true;
                if (block.expires_at && new Date(block.expires_at) > new Date()) return true;
                // Expired temporary block - clean up
                await this.delete(SUPABASE_CONFIG.tables.blockedDevices,
                    'device_fingerprint=eq.' + fp);
                return false;
            }
            return false;
        } catch (e) {
            return false;
        }
    },

    // Sync config to server
    async syncConfig(key, value) {
        return this.upsert(SUPABASE_CONFIG.tables.siteConfig, {
            config_key: key,
            config_value: value,
            updated_at: new Date().toISOString()
        });
    },

    // Get server config
    async getConfig(key) {
        const results = await this.select(SUPABASE_CONFIG.tables.siteConfig,
            'config_key=eq.' + key);
        return results && results.length > 0 ? results[0].config_value : null;
    },

    // Register/update active session
    async registerSession(sessionToken) {
        const fp = await this.getDeviceFingerprint();
        return this.upsert(SUPABASE_CONFIG.tables.activeSessions, {
            session_token: sessionToken,
            device_fingerprint: fp,
            ip_address: await this.getIP(),
            user_agent: navigator.userAgent,
            device_name: this.getDeviceName(),
            is_active: true,
            last_active_at: new Date().toISOString()
        });
    },

    // End a session
    async endSession(sessionToken) {
        return this.update(SUPABASE_CONFIG.tables.activeSessions,
            'session_token=eq.' + sessionToken,
            { is_active: false });
    },

    // Get all active sessions
    async getActiveSessions() {
        return this.select(SUPABASE_CONFIG.tables.activeSessions,
            'is_active=eq.true&order=last_active_at.desc');
    },

    // Get device name from user agent
    getDeviceName() {
        const ua = navigator.userAgent;
        if (/iPhone/.test(ua)) return 'iPhone';
        if (/iPad/.test(ua)) return 'iPad';
        if (/Android/.test(ua)) return 'Android';
        if (/Windows/.test(ua)) return 'Windows PC';
        if (/Mac/.test(ua)) return 'Mac';
        if (/Linux/.test(ua)) return 'Linux';
        return 'Unknown Device';
    },

    // Get access logs for admin panel
    async getAccessLogs(limit = 50) {
        return this.select(SUPABASE_CONFIG.tables.accessLogs,
            'order=created_at.desc&limit=' + limit);
    },

    // Get security events for admin panel
    async getSecurityEvents(limit = 100) {
        return this.select(SUPABASE_CONFIG.tables.securityEvents,
            'order=created_at.desc&limit=' + limit);
    },

    // Delete security events (with verification done in caller)
    async clearSecurityEvents() {
        return this.delete(SUPABASE_CONFIG.tables.securityEvents, 'id=gt.0');
    },

    // Get blocked devices list
    async getBlockedDevices() {
        return this.select(SUPABASE_CONFIG.tables.blockedDevices,
            'order=blocked_at.desc');
    },

    // Block a device on the server
    async blockDevice(fingerprint, ip, reason, blockType, expiresAt) {
        return this.upsert(SUPABASE_CONFIG.tables.blockedDevices, {
            device_fingerprint: fingerprint,
            ip_address: ip,
            reason: reason,
            block_type: blockType,
            expires_at: expiresAt
        });
    },

    // Unblock a device
    async unblockDevice(fingerprint) {
        return this.delete(SUPABASE_CONFIG.tables.blockedDevices,
            'device_fingerprint=eq.' + fingerprint);
    }
};
