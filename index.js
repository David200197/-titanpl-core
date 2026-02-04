// Titan Core Extension JS Wrapper
// This file wraps native functions and provides the higher-level Titan API

const _G = (typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : {}));

// --- Pre-initialize containers ---
// This prevents "Cannot destructure property 'ls' of 't.core' as it is undefined"
if (!_G.t) _G.t = {};
if (!_G.t.core) _G.t.core = {};
if (!_G.t["@titanpl/core"]) _G.t["@titanpl/core"] = {};

// --- Native Discovery ---
function findNatives() {
    const candidates = [
        _G.t["@titanpl/core"],
        _G.t.core,
        _G.t,
        _G
    ];
    for (const c of candidates) {
        // We look for a "raw" native object (has fs_read_file but is NOT our wrapper)
        if (c && typeof c.fs_read_file === 'function' && !c.__isTitanWrapper) {
            return c;
        }
    }
    return {};
}

const n = findNatives();

// Capture natives into a private scope to avoid recursion
const _fs_read = n.fs_read_file;
const _fs_write = n.fs_write_file;
const _fs_readdir = n.fs_readdir;
const _fs_mkdir = n.fs_mkdir;
const _fs_exists = n.fs_exists;
const _fs_stat = n.fs_stat;
const _fs_remove = n.fs_remove;
const _path_cwd = n.path_cwd;
const _crypto_hash = n.crypto_hash;
const _crypto_rand = n.crypto_random_bytes;
const _crypto_uuid = n.crypto_uuid;
const _crypto_enc = n.crypto_encrypt;
const _crypto_dec = n.crypto_decrypt;
const _crypto_hmac = n.crypto_hash_keyed;
const _crypto_cmp = n.crypto_compare;
const _os_info = n.os_info;
const _net_res = n.net_resolve;
const _net_ip = n.net_ip;
const _proc_info = n.proc_info;
const _proc_run = n.proc_run;
const _proc_kill = n.proc_kill;
const _proc_list = n.proc_list;
const _time_sleep = n.time_sleep;
const _ls_get = n.ls_get;
const _ls_set = n.ls_set;
const _ls_rem = n.ls_remove;
const _ls_clr = n.ls_clear;
const _ls_keys = n.ls_keys;
const _sess_get = n.session_get;
const _sess_set = n.session_set;
const _sess_del = n.session_delete;
const _sess_clr = n.session_clear;
const _v8_ser = n.serialize;
const _v8_des = n.deserialize;

// --- Helpers ---
const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const toB64 = (b) => {
    if (typeof b === 'string') return btoa(b);
    let s = '';
    for (let i = 0; i < b.byteLength; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
};
const fromB64 = (s) => {
    let b = atob(s), r = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) r[i] = b.charCodeAt(i);
    return r;
};

// --- Modules ---
export const fs = {
    readFile: (p) => { if (!_fs_read) throw "fs.readFile: native missing"; const r = _fs_read(p); if (typeof r === 'string' && r.startsWith("ERROR:")) throw r; return r; },
    writeFile: (p, c) => _fs_write && _fs_write(p, c),
    readdir: (p) => { try { return JSON.parse(_fs_readdir(p) || "[]"); } catch (e) { return []; } },
    mkdir: (p) => _fs_mkdir && _fs_mkdir(p),
    exists: (p) => _fs_exists && _fs_exists(p),
    stat: (p) => { try { return JSON.parse(_fs_stat(p) || "{}"); } catch (e) { return {}; } },
    remove: (p) => _fs_remove && _fs_remove(p)
};

export const path = {
    join: (...a) => a.filter(Boolean).map(x => String(x).replace(/\\/g, '/')).join('/').replace(/\/+/g, '/'),
    resolve: (...a) => { let r = path.join(...a); return (!r.startsWith('/') && !/^[a-zA-Z]:/.test(r) && _path_cwd) ? path.join(_path_cwd(), r) : r; },
    dirname: (p) => p.split('/').slice(0, -1).join('/') || '.',
    basename: (p) => p.split('/').pop() || '',
    extname: (p) => { let i = p.lastIndexOf('.'); return i > 0 ? p.slice(i) : ''; }
};

export const crypto = {
    hash: (a, d) => _crypto_hash ? _crypto_hash(a, d) : "",
    randomBytes: (s) => _crypto_rand ? _crypto_rand(s) : "",
    uuid: () => _crypto_uuid ? _crypto_uuid() : "",
    encrypt: (a, k, p) => { let r = _crypto_enc && _crypto_enc(a, JSON.stringify({ key: k, plaintext: p })); if (typeof r === 'string' && r.startsWith("ERROR:")) throw r.slice(6); return r; },
    decrypt: (a, k, c) => { let r = _crypto_dec && _crypto_dec(a, JSON.stringify({ key: k, ciphertext: c })); if (typeof r === 'string' && r.startsWith("ERROR:")) throw r.slice(6); return r; },
    hashKeyed: (a, k, m) => { let r = _crypto_hmac && _crypto_hmac(a, JSON.stringify({ key: k, message: m })); if (typeof r === 'string' && r.startsWith("ERROR:")) throw r.slice(6); return r; },
    compare: (a, b) => _crypto_cmp ? _crypto_cmp(a, b) : a === b
};

export const os = {
    info: () => { try { return JSON.parse(_os_info() || "{}"); } catch (e) { return {}; } },
    platform: () => os.info().platform || "unknown",
    cpus: () => os.info().cpus || 1,
    totalMemory: () => os.info().totalMemory || 0,
    tmpdir: () => os.info().tempDir || "/tmp"
};

export const ls = {
    get: (k) => _ls_get ? _ls_get(k) : null,
    set: (k, v) => _ls_set && _ls_set(k, String(v)),
    remove: (k) => _ls_rem && _ls_rem(k),
    clear: () => _ls_clr && _ls_clr(),
    keys: () => { try { return JSON.parse(_ls_keys() || "[]"); } catch (e) { return []; } },
    serialize: (v) => _v8_ser ? _v8_ser(v) : null,
    deserialize: (b) => _v8_des ? _v8_des(b) : null,
    setObject: (k, v) => ls.set(k, toB64(ls.serialize(v))),
    getObject: (k) => { let b = ls.get(k); return b ? ls.deserialize(fromB64(b)) : null; }
};

export const response = (o) => ({ _isResponse: true, status: o.status || 200, headers: o.headers || {}, body: o.body || "" });
response.json = (c, o = {}) => response({ ...o, headers: { "Content-Type": "application/json", ...(o.headers || {}) }, body: JSON.stringify(c) });
response.text = (c, o = {}) => response({ ...o, headers: { "Content-Type": "text/plain", ...(o.headers || {}) }, body: String(c) });
response.html = (c, o = {}) => response({ ...o, headers: { "Content-Type": "text/html", ...(o.headers || {}) }, body: String(c) });

export const proc = {
    pid: () => { try { return JSON.parse(_proc_info()).pid; } catch (e) { return 0; } },
    run: (c, a = [], d = "") => { let r = _proc_run && _proc_run(c, JSON.stringify({ args: a, cwd: d })); try { return JSON.parse(r); } catch (e) { throw r; } }
};

// --- Core Wrapper ---
export const core = {
    fs, path, crypto, os, ls, response, proc,
    serialize: ls.serialize,
    deserialize: ls.deserialize,
    __isTitanWrapper: true
};

// --- 3-Way Access Implementation ---
// 1. Named Exports: Already handled by 'export' above.
// 2. t.core.*
// 3. t.* (Direct)
(function applyGlobals() {
    const t = _G.t;
    if (!t) return;

    const set = (obj, k, v) => {
        try { obj[k] = v; } catch (e) {
            try { Object.defineProperty(obj, k, { value: v, writable: true, configurable: true, enumerable: true }); } catch (i) { }
        }
    };

    // Patch t.core and t["@titanpl/core"]
    const targets = [t.core, t["@titanpl/core"]];
    targets.forEach(tgt => {
        if (!tgt) return;
        Object.keys(core).forEach(k => set(tgt, k, core[k]));
    });

    // Patch root t.* (Direct shortcuts)
    Object.keys(core).forEach(k => {
        if (!k.startsWith("__")) set(t, k, core[k]);
    });
})();

export default core;