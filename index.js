// Titan Core Extension JS Wrapper
// This file wraps native functions and provides the higher-level Titan API

const _global = (typeof t !== 'undefined' ? t : (typeof globalThis !== 'undefined' ? globalThis.t : (typeof window !== 'undefined' ? window.t : {})));

// --- Native discovery ---
function findNatives() {
    const candidates = [
        _global["@titanpl/core"],
        _global.core,
        _global,
        globalThis
    ];
    for (const c of candidates) {
        if (c && typeof c.fs_read_file === 'function' && !c.__isTitanWrapper) {
            return c;
        }
    }
    return null;
}

const n = findNatives() || {};

// CAPTURE NATIVES IMMEDIATELY to avoid recursion
const _n_fs_read_file = n.fs_read_file;
const _n_fs_write_file = n.fs_write_file;
const _n_fs_readdir = n.fs_readdir;
const _n_fs_mkdir = n.fs_mkdir;
const _n_fs_exists = n.fs_exists;
const _n_fs_stat = n.fs_stat;
const _n_fs_remove = n.fs_remove;
const _n_path_cwd = n.path_cwd;
const _n_crypto_hash = n.crypto_hash;
const _n_crypto_random_bytes = n.crypto_random_bytes;
const _n_crypto_uuid = n.crypto_uuid;
const _n_crypto_encrypt = n.crypto_encrypt;
const _n_crypto_decrypt = n.crypto_decrypt;
const _n_crypto_hash_keyed = n.crypto_hash_keyed;
const _n_crypto_compare = n.crypto_compare;
const _n_os_info = n.os_info;
const _n_net_resolve = n.net_resolve;
const _n_net_ip = n.net_ip;
const _n_proc_info = n.proc_info;
const _n_proc_run = n.proc_run;
const _n_proc_kill = n.proc_kill;
const _n_proc_list = n.proc_list;
const _n_time_sleep = n.time_sleep;
const _n_ls_get = n.ls_get;
const _n_ls_set = n.ls_set;
const _n_ls_remove = n.ls_remove;
const _n_ls_clear = n.ls_clear;
const _n_ls_keys = n.ls_keys;
const _n_session_get = n.session_get;
const _n_session_set = n.session_set;
const _n_session_delete = n.session_delete;
const _n_session_clear = n.session_clear;
const _n_serialize = n.serialize;
const _n_deserialize = n.deserialize;

// --- Helpers ---
const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const local_btoa = (input) => {
    let str = String(input);
    let output = '';
    for (let i = 0; i < str.length; i += 3) {
        const char1 = str.charCodeAt(i);
        const char2 = str.charCodeAt(i + 1);
        const char3 = str.charCodeAt(i + 2);
        const enc1 = char1 >> 2;
        const enc2 = ((char1 & 3) << 4) | (char2 >> 4);
        let enc3 = ((char2 & 15) << 2) | (char3 >> 6);
        let enc4 = char3 & 63;
        if (isNaN(char2)) enc3 = enc4 = 64;
        else if (isNaN(char3)) enc4 = 64;
        output += b64chars.charAt(enc1) + b64chars.charAt(enc2) + (enc3 === 64 ? '=' : b64chars.charAt(enc3)) + (enc4 === 64 ? '=' : b64chars.charAt(enc4));
    }
    return output;
};
const local_atob = (input) => {
    let str = String(input).replace(/[=]+$/, '');
    let output = '';
    if (str.length % 4 === 1) throw new Error("'atob' failed");
    for (let bc = 0, bs, buffer, idx = 0; buffer = str.charAt(idx++); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0) {
        buffer = b64chars.indexOf(buffer);
    }
    return output;
};

// --- FS ---
export const fs = {
    readFile: (p) => {
        if (typeof _n_fs_read_file !== 'function') throw new Error("native fs_read_file not found");
        const res = _n_fs_read_file(p);
        if (typeof res === 'string' && res.startsWith("ERROR:")) throw new Error(res);
        return res;
    },
    writeFile: (p, c) => _n_fs_write_file && _n_fs_write_file(p, c),
    readdir: (p) => {
        const res = _n_fs_readdir && _n_fs_readdir(p);
        try { return JSON.parse(res || "[]"); } catch (e) { return []; }
    },
    mkdir: (p) => _n_fs_mkdir && _n_fs_mkdir(p),
    exists: (p) => _n_fs_exists && _n_fs_exists(p),
    stat: (p) => {
        const res = _n_fs_stat && _n_fs_stat(p);
        try { return JSON.parse(res || "{}"); } catch (e) { return {}; }
    },
    remove: (p) => _n_fs_remove && _n_fs_remove(p)
};

// --- Path ---
export const path = {
    join: (...args) => args.map((p, i) => {
        if (!p) return '';
        let s = String(p).replace(/\\/g, '/');
        if (i === 0) return s.replace(/\/+$/, '');
        return s.replace(/^\/+|\/+$/g, '');
    }).filter(x => x).join('/'),
    resolve: (...args) => {
        let r = path.join(...args);
        if (!r.startsWith('/') && !/^[a-zA-Z]:/.test(r) && _n_path_cwd) {
            r = path.join(_n_path_cwd(), r);
        }
        return r;
    },
    dirname: (p) => p.split('/').slice(0, -1).join('/') || '.',
    basename: (p) => p.split('/').pop() || '',
    extname: (p) => { const parts = p.split('.'); return parts.length > 1 ? '.' + parts.pop() : ''; }
};

// --- Crypto ---
export const crypto = {
    hash: (a, d) => _n_crypto_hash ? _n_crypto_hash(a, d) : "",
    randomBytes: (s) => _n_crypto_random_bytes ? _n_crypto_random_bytes(s) : "",
    uuid: () => _n_crypto_uuid ? _n_crypto_uuid() : "",
    encrypt: (a, k, p) => {
        const res = _n_crypto_encrypt && _n_crypto_encrypt(a, JSON.stringify({ key: k, plaintext: p }));
        if (typeof res === 'string' && res.startsWith("ERROR:")) throw new Error(res.slice(6));
        return res;
    },
    decrypt: (a, k, c) => {
        const res = _n_crypto_decrypt && _n_crypto_decrypt(a, JSON.stringify({ key: k, ciphertext: c }));
        if (typeof res === 'string' && res.startsWith("ERROR:")) throw new Error(res.slice(6));
        return res;
    },
    hashKeyed: (a, k, m) => {
        const res = _n_crypto_hash_keyed && _n_crypto_hash_keyed(a, JSON.stringify({ key: k, message: m }));
        if (typeof res === 'string' && res.startsWith("ERROR:")) throw new Error(res.slice(6));
        return res;
    },
    compare: (a, b) => _n_crypto_compare ? _n_crypto_compare(a, b) : a === b
};

// --- Buffer ---
export const buffer = {
    fromBase64: (s) => {
        const bin = local_atob(s);
        const res = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) res[i] = bin.charCodeAt(i);
        return res;
    },
    toBase64: (b) => {
        if (typeof b === 'string') return local_btoa(b);
        let s = '';
        const len = b.byteLength;
        for (let i = 0; i < len; i++) s += String.fromCharCode(b[i]);
        return local_btoa(s);
    }
};

// --- OS ---
export const os = {
    info: () => { try { return JSON.parse(_n_os_info() || "{}"); } catch (e) { return {}; } },
    platform: () => os.info().platform || "unknown",
    cpus: () => os.info().cpus || 1,
    totalMemory: () => os.info().totalMemory || 0,
    freeMemory: () => os.info().freeMemory || 0,
    tmpdir: () => os.info().tempDir || "/tmp"
};

// --- Net ---
export const net = {
    resolveDNS: (h) => {
        const res = _n_net_resolve && _n_net_resolve(h);
        try { return JSON.parse(res || "[]"); } catch (e) { return []; }
    },
    ip: () => _n_net_ip ? _n_net_ip() : "127.0.0.1"
};

// --- Proc ---
export const proc = {
    info: () => { try { return JSON.parse(_n_proc_info() || "{}"); } catch (e) { return {}; } },
    pid: () => proc.info().pid || 0,
    run: (cmd, args = [], cwd = "") => {
        const res = _n_proc_run && _n_proc_run(cmd, JSON.stringify({ args, cwd }));
        try { return JSON.parse(res || "{}"); } catch (e) { throw new Error(res || "unknown error"); }
    },
    kill: (pid) => _n_proc_kill && _n_proc_kill(Number(pid)),
    list: () => {
        const res = _n_proc_list && _n_proc_list();
        try { return JSON.parse(res || "[]"); } catch (e) { return []; }
    }
};

// --- Time ---
export const time = {
    sleep: (ms) => _n_time_sleep && _n_time_sleep(Number(ms)),
    now: () => Date.now()
};

// --- LS & V8 ---
export const ls = {
    get: (k) => _n_ls_get ? _n_ls_get(k) : null,
    set: (k, v) => _n_ls_set && _n_ls_set(k, String(v)),
    remove: (k) => _n_ls_remove && _n_ls_remove(k),
    clear: () => _n_ls_clear && _n_ls_clear(),
    keys: () => { try { return JSON.parse(_n_ls_keys() || "[]"); } catch (e) { return []; } },
    serialize: (v) => _n_serialize ? _n_serialize(v) : null,
    deserialize: (b) => _n_deserialize ? _n_deserialize(b) : null,
    setObject: (k, v) => ls.set(k, buffer.toBase64(ls.serialize(v))),
    getObject: (k) => {
        const b64 = ls.get(k);
        if (!b64) return null;
        try { return ls.deserialize(buffer.fromBase64(b64)); } catch (e) { return null; }
    }
};

export const serialize = (v) => ls.serialize(v);
export const deserialize = (b) => ls.deserialize(b);

// --- Session ---
export const session = {
    get: (id, k) => _n_session_get ? _n_session_get(id, k) : null,
    set: (id, k, v) => _n_session_set && _n_session_set(id, JSON.stringify({ key: k, value: String(v) })),
    delete: (id, k) => _n_session_delete && _n_session_delete(id, k),
    clear: (id) => _n_session_clear && _n_session_clear(id)
};

// --- Cookies ---
export const cookies = {
    get: (req, name) => {
        if (!req || !req.headers || !req.headers.cookie) return null;
        const cookies = req.headers.cookie.split(';');
        for (let c of cookies) {
            const [k, v] = c.trim().split('=');
            if (k === name) return decodeURIComponent(v);
        }
        return null;
    },
    set: (res, name, value, options = {}) => {
        if (!res) return;
        let cookie = `${name}=${encodeURIComponent(value)}`;
        if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
        if (options.path) cookie += `; Path=${options.path}`;
        if (options.httpOnly) cookie += `; HttpOnly`;
        if (options.secure) cookie += `; Secure`;
        if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
        if (res._isResponse) {
            if (!res.headers) res.headers = {};
            res.headers['Set-Cookie'] = cookie;
        }
    }
};

// --- Response ---
export const response = (opt) => ({ _isResponse: true, status: opt.status || 200, headers: opt.headers || {}, body: opt.body || "" });
response.text = (c, o = {}) => response({ ...o, headers: { "Content-Type": "text/plain", ...(o.headers || {}) }, body: String(c) });
response.json = (c, o = {}) => response({ ...o, headers: { "Content-Type": "application/json", ...(o.headers || {}) }, body: JSON.stringify(c) });
response.html = (c, o = {}) => response({ ...o, headers: { "Content-Type": "text/html; charset=utf-8", ...(o.headers || {}) }, body: String(c) });
response.redirect = (u, s = 302) => response({ status: s, headers: { "Location": u }, body: "" });

// --- URL ---
class TitanURLSearchParams {
    constructor(init = '') {
        this._params = {};
        if (typeof init === 'string') {
            const query = init.startsWith('?') ? init.slice(1) : init;
            query.split('&').forEach(pair => {
                const [key, value] = pair.split('=').map(decodeURIComponent);
                if (key) this._params[key] = value || '';
            });
        }
    }
    get(key) { return this._params[key] || null; }
    set(key, value) { this._params[key] = String(value); }
    toString() { return Object.entries(this._params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&'); }
}
export const url = {
    parse: (str) => { try { return new URL(str); } catch (e) { return { pathname: str }; } },
    SearchParams: TitanURLSearchParams
};

// --- Unified Core ---
export const core = {
    fs, path, crypto, buffer, os, net, proc, time, ls, session, cookies, response, url,
    serialize, deserialize,
    __isTitanWrapper: true
};

// --- Global Attachment ---
if (typeof t !== 'undefined' || typeof globalThis.t !== 'undefined') {
    const target = (typeof t !== 'undefined' ? t : globalThis.t);
    if (!target.core) target.core = {};
    Object.assign(target.core, core);
    if (target["@titanpl/core"]) Object.assign(target["@titanpl/core"], core);
    else target["@titanpl/core"] = core;
    Object.keys(core).forEach(k => {
        if (!k.startsWith("__")) try { target[k] = core[k]; } catch (e) { }
    });
}

export default core;