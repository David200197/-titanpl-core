// Early initialization of t.core to prevent destructuring errors during load
(function () {
    const _t = (typeof t !== 'undefined' ? t : (typeof globalThis !== 'undefined' ? globalThis.t : null));
    if (_t) {
        if (!_t.core) _t.core = {};
        // Placeholder for early access to modules to prevent destructuring failures
        const modules = ['fs', 'path', 'crypto', 'os', 'net', 'proc', 'time', 'url', 'buffer', 'ls', 'session', 'cookies', 'response'];
        modules.forEach(m => { if (!_t.core[m]) _t.core[m] = {}; });
    }
})();

const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function local_btoa(input) {
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

        if (isNaN(char2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(char3)) {
            enc4 = 64;
        }

        output += b64chars.charAt(enc1) + b64chars.charAt(enc2) +
            (enc3 === 64 ? '=' : b64chars.charAt(enc3)) +
            (enc4 === 64 ? '=' : b64chars.charAt(enc4));
    }

    return output;
}

function local_atob(input) {
    let str = String(input).replace(/[=]+$/, '');
    let output = '';

    if (str.length % 4 === 1) {
        throw new Error("'atob' failed: The string to be decoded is not correctly encoded.");
    }

    for (let bc = 0, bs, buffer, idx = 0; buffer = str.charAt(idx++); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer,
        bc++ % 4) ? output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0) {
        buffer = b64chars.indexOf(buffer);
    }

    return output;
}

function local_utf8_encode(string) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(string);
    // basic polyfill
    let res = [];
    for (let i = 0; i < string.length; i++) {
        let c = string.charCodeAt(i);
        if (c < 128) res.push(c);
        else if (c < 2048) res.push((c >> 6) | 192, (c & 63) | 128);
        else res.push((c >> 12) | 224, ((c >> 6) & 63) | 128, (c & 63) | 128);
    }
    return new Uint8Array(res);
}

function local_utf8_decode(buffer) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(buffer);
    return String.fromCharCode.apply(null, buffer);
}

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
    let hex = [];
    for (let i = 0; i < bytes.length; i++) {
        let current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}

// Native bindings are loaded by the runtime into t["@titanpl/core"] or t.core
const getT = () => {
    if (typeof t !== 'undefined') return t;
    if (typeof globalThis !== 'undefined' && globalThis.t) return globalThis.t;
    return null;
};
const _t = getT();
const natives = (_t && (_t["@titanpl/core"] || _t.core)) || {};

// Native Function bindings
const native_fs_read_file = natives.fs_read_file;
const native_fs_write_file = natives.fs_write_file;
const native_fs_readdir = natives.fs_readdir;
const native_fs_mkdir = natives.fs_mkdir;
const native_fs_exists = natives.fs_exists;
const native_fs_stat = natives.fs_stat;
const native_fs_remove = natives.fs_remove;
const native_path_cwd = natives.path_cwd;

const native_crypto_hash = natives.crypto_hash;
const native_crypto_random_bytes = natives.crypto_random_bytes;
const native_crypto_uuid = natives.crypto_uuid;
const native_crypto_encrypt = natives.crypto_encrypt;
const native_crypto_decrypt = natives.crypto_decrypt;
const native_crypto_hash_keyed = natives.crypto_hash_keyed;
const native_crypto_compare = natives.crypto_compare;

const native_os_info = natives.os_info;
const native_net_resolve = natives.net_resolve;
const native_net_ip = natives.net_ip;
const native_proc_info = natives.proc_info;
const native_proc_run = natives.proc_run;
const native_proc_kill = natives.proc_kill;
const native_proc_list = natives.proc_list;
const native_time_sleep = natives.time_sleep;

const native_ls_get = natives.ls_get;
const native_ls_set = natives.ls_set;
const native_ls_remove = natives.ls_remove;
const native_ls_clear = natives.ls_clear;
const native_ls_keys = natives.ls_keys;

const native_session_get = natives.session_get;
const native_session_set = natives.session_set;
const native_session_delete = natives.session_delete;
const native_session_clear = natives.session_clear;

// --- FS ---
const fs = {
    readFile: (path) => {
        if (!native_fs_read_file) throw new Error("Native fs_read_file not found");
        const res = native_fs_read_file(path);
        if (res && res.startsWith("ERROR:")) throw new Error(res);
        return res;
    },
    writeFile: (path, content) => {
        if (!native_fs_write_file) throw new Error("Native fs_write_file not found");
        native_fs_write_file(path, content);
    },
    readdir: (path) => {
        if (!native_fs_readdir) throw new Error("Native fs_readdir not found");
        const res = native_fs_readdir(path);
        try { return JSON.parse(res); } catch (e) { return []; }
    },
    mkdir: (path) => {
        if (!native_fs_mkdir) throw new Error("Native fs_mkdir not found");
        native_fs_mkdir(path);
    },
    exists: (path) => {
        if (!native_fs_exists) throw new Error("Native fs_exists not found");
        return native_fs_exists(path);
    },
    stat: (path) => {
        if (!native_fs_stat) throw new Error("Native fs_stat not found");
        const res = native_fs_stat(path);
        try { return JSON.parse(res); } catch (e) { return {}; }
    },
    remove: (path) => {
        if (!native_fs_remove) throw new Error("Native fs_remove not found");
        native_fs_remove(path);
    }
};

// --- Path ---
const path = {
    join: (...args) => {
        return args
            .map((part, i) => {
                if (!part) return '';
                let p = part.replace(/\\/g, '/');
                if (i === 0) return p.trim().replace(/[\/]*$/g, '');
                return p.trim().replace(/(^[\/]*|[\/]*$)/g, '');
            })
            .filter(x => x.length)
            .join('/');
    },
    resolve: (...args) => {
        let resolved = '';
        for (let arg of args) { resolved = path.join(resolved, arg); }
        if (!resolved.startsWith('/')) {
            const isWindowsAbs = /^[a-zA-Z]:\\/.test(resolved) || resolved.startsWith('\\');
            if (!isWindowsAbs && native_path_cwd) {
                const cwd = native_path_cwd();
                if (cwd) resolved = path.join(cwd, resolved);
            }
        }
        return resolved;
    },
    extname: (p) => {
        const parts = p.split('.');
        return parts.length > 1 && !p.startsWith('.') ? '.' + parts.pop() : '';
    },
    dirname: (p) => {
        const parts = p.split('/');
        parts.pop();
        return parts.join('/') || '.';
    },
    basename: (p) => p.split('/').pop()
};

// --- Crypto ---
const crypto = {
    hash: (algo, data) => native_crypto_hash ? native_crypto_hash(algo, data) : "",
    randomBytes: (size) => native_crypto_random_bytes ? native_crypto_random_bytes(size) : "",
    uuid: () => native_crypto_uuid ? native_crypto_uuid() : "",
    base64: {
        encode: (str) => local_btoa(str),
        decode: (str) => local_atob(str),
    },
    encrypt: (algorithm, key, plaintext) => {
        if (!native_crypto_encrypt) throw new Error("Native crypto_encrypt not found");
        const res = native_crypto_encrypt(algorithm, JSON.stringify({ key, plaintext }));
        if (res.startsWith("ERROR:")) throw new Error(res.substring(6));
        return res;
    },
    decrypt: (algorithm, key, ciphertext) => {
        if (!native_crypto_decrypt) throw new Error("Native crypto_decrypt not found");
        const res = native_crypto_decrypt(algorithm, JSON.stringify({ key, ciphertext }));
        if (res.startsWith("ERROR:")) throw new Error(res.substring(6));
        return res;
    },
    hashKeyed: (algorithm, key, message) => {
        if (!native_crypto_hash_keyed) throw new Error("Native crypto_hash_keyed not found");
        const res = native_crypto_hash_keyed(algorithm, JSON.stringify({ key, message }));
        if (res.startsWith("ERROR:")) throw new Error(res.substring(6));
        return res;
    },
    compare: (a, b) => {
        if (native_crypto_compare) return native_crypto_compare(a, b);
        if (a.length !== b.length) return false;
        let mismatch = 0;
        for (let i = 0; i < a.length; ++i) mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
        return mismatch === 0;
    }
};

// --- Buffer ---
const buffer = {
    fromBase64: (str) => {
        const binary = local_atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    },
    toBase64: (bytes) => {
        let binary = '';
        if (typeof bytes === 'string') return local_btoa(bytes);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
        return local_btoa(binary);
    },
    fromHex: (str) => hexToBytes(str),
    toHex: (bytes) => (typeof bytes === 'string') ? bytesToHex(local_utf8_encode(bytes)) : bytesToHex(bytes),
    fromUtf8: (str) => local_utf8_encode(str),
    toUtf8: (bytes) => local_utf8_decode(bytes)
};

// --- Local Storage ---
const ls = {
    get: (key) => native_ls_get ? native_ls_get(key) : null,
    set: (key, value) => native_ls_set && native_ls_set(key, String(value)),
    remove: (key) => native_ls_remove && native_ls_remove(key),
    clear: () => native_ls_clear && native_ls_clear(),
    keys: () => {
        if (!native_ls_keys) return [];
        try { return JSON.parse(native_ls_keys()); } catch (e) { return []; }
    },
    setObject: (key, value) => ls.set(key, buffer.toBase64(ls.serialize(value))),
    getObject: (key) => {
        const b64 = ls.get(key);
        if (!b64) return null;
        try { return ls.deserialize(buffer.fromBase64(b64)); } catch (e) { return null; }
    },
    serialize: (value) => natives.serialize ? natives.serialize(value) : null,
    deserialize: (bytes) => natives.deserialize ? natives.deserialize(bytes) : null,
};

// --- Sessions ---
const session = {
    get: (sessionId, key) => native_session_get ? native_session_get(sessionId, key) : null,
    set: (sessionId, key, value) => native_session_set && native_session_set(sessionId, key, String(value)),
    delete: (sessionId, key) => native_session_delete && native_session_delete(sessionId, key),
    clear: (sessionId) => native_session_clear && native_session_clear(sessionId)
};

// --- Cookies ---
const cookies = {
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
        // Note: res.setHeader must be provided by t.response or the runtime
        if (res._isResponse) {
            if (!res.headers) res.headers = {};
            res.headers['Set-Cookie'] = cookie;
        }
    }
};

// --- Response ---
const response = (options) => ({
    _isResponse: true, status: options.status || 200, headers: options.headers || {}, body: options.body || ""
});
response.text = (content, options = {}) => response({ ...options, headers: { "Content-Type": "text/plain", ...(options.headers || {}) }, body: content });
response.html = (content, options = {}) => response({ ...options, headers: { "Content-Type": "text/html; charset=utf-8", ...(options.headers || {}) }, body: content });
response.json = (content, options = {}) => response({ ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) }, body: JSON.stringify(content) });
response.redirect = (url, status = 302) => response({ status, headers: { "Location": url }, body: "" });

// --- OS ---
const os = {
    platform: () => native_os_info ? JSON.parse(native_os_info()).platform : "unknown",
    cpus: () => native_os_info ? JSON.parse(native_os_info()).cpus : 1,
};

// --- Net ---
const net = {
    resolveDNS: (hostname) => native_net_resolve ? JSON.parse(native_net_resolve(hostname)) : [],
    ip: () => native_net_ip ? native_net_ip() : "127.0.0.1",
};

// --- Proc ---
const proc = {
    pid: () => native_proc_info ? JSON.parse(native_proc_info()).pid : 0,
    run: (command, args = [], cwd) => {
        if (!native_proc_run) throw new Error("Native proc_run not found");
        const res = native_proc_run(command, JSON.stringify({ args, cwd: cwd || "" }));
        try { return JSON.parse(res); } catch (e) { throw new Error(`Process error: ${res}`); }
    },
    kill: (pid) => native_proc_kill ? native_proc_kill(pid) : false,
    list: () => {
        if (!native_proc_list) return [];
        try { return JSON.parse(native_proc_list()); } catch (e) { return []; }
    }
};

// --- Time ---
const time = {
    sleep: (ms) => native_time_sleep && native_time_sleep(ms),
    now: () => Date.now(),
};

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

const url = {
    parse: (str) => {
        try { return new URL(str); } catch (e) { return { pathname: str }; }
    },
    SearchParams: TitanURLSearchParams
};

// --- Unified Core ---
const core = { fs, path, crypto, os, net, proc, time, url, buffer, ls, session, cookies, response };

if (_t) {
    _t.core = core;
    _t.fs = fs;
    _t.path = path;
    _t.crypto = crypto;
    _t.os = os;
    _t.net = net;
    _t.proc = proc;
    _t.time = time;
    _t.url = url;
    _t.buffer = buffer;
    _t.ls = ls;
    _t.session = session;
    _t.cookies = cookies;
    _t.response = response;
    _t["@titanpl/core"] = core;
}

export {
    fs, path, crypto, os, net, proc, time, url, buffer, ls, session, cookies, response, core, TitanURLSearchParams
};