// Titan Core Extension JS Wrapper
// This file wraps native functions and provides the higher-level Titan API

const _G = (typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : {}));

/**
 * Native lookup - Searches for functions defined in titan.json and injected by the runtime.
 */
function getNative(name) {
    const t = _G.t || _G.Titan;

    // Try globalThis first (common for Titan natives)
    if (typeof _G[name] === 'function') return _G[name];

    // Check extension namespace (Natives are injected here by Runtime)
    if (t && t["@titanpl/core"] && typeof t["@titanpl/core"][name] === 'function') return t["@titanpl/core"][name];

    // Try t.native (recommended by Titan template)
    if (t && t.native && typeof t.native[name] === 'function') return t.native[name];

    // Try t direct
    if (t && typeof t[name] === 'function' && !t.__isTitanWrapper) return t[name];

    return null;
}

// --- Base64 Utilities ---
const _b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const _toB64 = (input) => {
    let output = ''; let chr1, chr2, chr3, enc1, enc2, enc3, enc4; let i = 0;
    const data = (typeof input === 'string') ? input : String.fromCharCode.apply(null, input);
    while (i < data.length) {
        chr1 = data.charCodeAt(i++); chr2 = data.charCodeAt(i++); chr3 = data.charCodeAt(i++);
        enc1 = chr1 >> 2; enc2 = ((chr1 & 3) << 4) | (chr2 >> 4); enc3 = ((chr2 & 15) << 2) | (chr3 >> 6); enc4 = chr3 & 63;
        if (isNaN(chr2)) enc3 = enc4 = 64; else if (isNaN(chr3)) enc4 = 64;
        output += _b64chars.charAt(enc1) + _b64chars.charAt(enc2) + _b64chars.charAt(enc3) + _b64chars.charAt(enc4);
    }
    return output;
};
const _fromB64 = (input) => {
    let output = ''; let i = 0; const data = String(input || "").replace(/[^A-Za-z0-9\+\/\=]/g, "");
    while (i < data.length) {
        let enc1 = _b64chars.indexOf(data.charAt(i++)); let enc2 = _b64chars.indexOf(data.charAt(i++));
        let enc3 = _b64chars.indexOf(data.charAt(i++)); let enc4 = _b64chars.indexOf(data.charAt(i++));
        let chr1 = (enc1 << 2) | (enc2 >> 4); let chr2 = ((enc2 & 15) << 4) | (enc3 >> 2); let chr3 = ((enc3 & 3) << 6) | enc4;
        output += String.fromCharCode(chr1); if (enc3 != 64) output += String.fromCharCode(chr2); if (enc4 != 64) output += String.fromCharCode(chr3);
    }
    const res = new Uint8Array(output.length);
    for (let j = 0; j < output.length; j++) res[j] = output.charCodeAt(j);
    return res;
};

// --- Modules ---
export const fs = {
    readFile: (p) => { const f = getNative("fs_read_file"); if (!f) throw new Error("fs_read_file missing"); const r = f(p); if (typeof r === 'string' && r.startsWith("ERROR:")) throw new Error(r); return r; },
    writeFile: (p, c) => { const f = getNative("fs_write_file"); f && f(p, c); },
    readdir: (p) => { const f = getNative("fs_readdir"); try { return JSON.parse(f ? f(p) : "[]"); } catch (e) { return []; } },
    mkdir: (p) => { const f = getNative("fs_mkdir"); f && f(p); },
    exists: (p) => { const f = getNative("fs_exists"); return f ? f(p) : false; },
    stat: (p) => { const f = getNative("fs_stat"); try { return JSON.parse(f ? f(p) : "{}"); } catch (e) { return {}; } },
    remove: (p) => { const f = getNative("fs_remove"); f && f(p); }
};

export const path = {
    join: (...a) => a.filter(Boolean).map(x => String(x).replace(/\\/g, '/')).join('/').replace(/\/+/g, '/'),
    resolve: (...a) => { let r = path.join(...a); const f = getNative("path_cwd"); return (!r.startsWith('/') && !/^[a-zA-Z]:/.test(r) && f) ? path.join(f(), r) : r; },
    dirname: (p) => p.split('/').slice(0, -1).join('/') || '.',
    basename: (p) => p.split('/').pop() || '',
    extname: (p) => { let i = p.lastIndexOf('.'); return i > 0 ? p.slice(i) : ''; }
};

export const crypto = {
    hash: (a, d) => { const f = getNative("crypto_hash"); return f ? f(a, d) : ""; },
    randomBytes: (s) => { const f = getNative("crypto_random_bytes"); return f ? f(s) : ""; },
    uuid: () => { const f = getNative("crypto_uuid"); return f ? f() : ""; },
    encrypt: (a, k, p) => { const f = getNative("crypto_encrypt"); const r = f ? f(a, JSON.stringify({ key: k, plaintext: p })) : null; return (typeof r === 'string' && r.startsWith("ERROR:")) ? (() => { throw new Error(r.slice(6)); })() : r; },
    decrypt: (a, k, c) => { const f = getNative("crypto_decrypt"); const r = f ? f(a, JSON.stringify({ key: k, ciphertext: c })) : null; return (typeof r === 'string' && r.startsWith("ERROR:")) ? (() => { throw new Error(r.slice(6)); })() : r; },
    compare: (a, b) => a === b
};

export const ls = {
    get: (k) => { const f = getNative("ls_get"); return f ? f(k) : null; },
    set: (k, v) => { const f = getNative("ls_set"); f && f(k, String(v)); },
    remove: (k) => { const f = getNative("ls_remove"); f && f(k); },
    clear: () => { const f = getNative("ls_clear"); f && f(); },
    keys: () => { const f = getNative("ls_keys"); try { return JSON.parse(f ? f() : "[]"); } catch (e) { return []; } },
    serialize: (v) => { const f = getNative("serialize"); return f ? f(v) : null; },
    deserialize: (b) => { const f = getNative("deserialize"); return f ? f(b) : null; },
    setObject: (k, v) => { const s = ls.serialize(v); if (s) ls.set(k, _toB64(s)); },
    getObject: (k) => { const b = ls.get(k); if (!b) return null; try { return ls.deserialize(_fromB64(b)); } catch (e) { return null; } }
};

export const response = (o) => ({ _isResponse: true, status: o.status || 200, headers: o.headers || {}, body: o.body || "" });
response.json = (c, o = {}) => response({ ...o, headers: { "Content-Type": "application/json", ...(o.headers || {}) }, body: JSON.stringify(c) });

export const core = { fs, path, crypto, ls, response, __isTitanWrapper: true };

/**
 * 3-Way Global Initialization
 */
export const sync = () => {
    const t = _G.t || (typeof t !== 'undefined' ? t : null);
    if (!t) {
        // If t is missing, we can't attach.
        return;
    }

    // Helper to set property preventing errors on restricted objects
    const set = (obj, k, v) => {
        try { obj[k] = v; } catch (e) {
            try { Object.defineProperty(obj, k, { value: v, writable: true, configurable: true, enumerable: true }); } catch (i) { }
        }
    };

    // 1. t.core.*
    if (!t.core) t.core = {};
    Object.assign(t.core, core);

    // 2. t["@titanpl/core"].*
    if (!t["@titanpl/core"]) t["@titanpl/core"] = {};
    Object.assign(t["@titanpl/core"], core);

    // 3. Direct t.*
    Object.keys(core).forEach(k => {
        if (!k.startsWith("__")) set(t, k, core[k]);
    });
};

// Auto-sync on load
sync();

export default core;