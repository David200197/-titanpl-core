// Titan Core Library
// Provides standard library features using native bindings.

// Native bindings are loaded by the runtime into t["@titanpl/core"]
// We capture them here before defining our high-level API.
const natives = t["@titanpl/core"] || {};

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
const native_os_info = natives.os_info;
const native_net_resolve = natives.net_resolve;
const native_net_ip = natives.net_ip;
const native_proc_info = natives.proc_info;
const native_time_sleep = natives.time_sleep;

// --- FS ---
const fs = {
    readFile: (path) => {
        if (!native_fs_read_file) throw new Error("Native fs_read_file not found");
        const res = native_fs_read_file(path);
        if (res.startsWith("ERROR:")) throw new Error(res);
        return res;
    },
    writeFile: (path, content) => {
        if (!native_fs_write_file) throw new Error("Native fs_write_file not found");
        native_fs_write_file(path, content);
    },
    readdir: (path) => {
        if (!native_fs_readdir) throw new Error("Native fs_readdir not found");
        const res = native_fs_readdir(path);
        // Runtime might return empty string on error or failures, or "[]"
        try {
            return JSON.parse(res);
        } catch (e) {
            return [];
        }
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
        try {
            return JSON.parse(res);
        } catch (e) {
            return {};
        }
    },
    remove: (path) => {
        if (!native_fs_remove) throw new Error("Native fs_remove not found");
        native_fs_remove(path);
    }
};

// --- Path ---
// Basic implementation for POSIX-like paths (Titan mostly runs on servers/containers)
const path = {
    join: (...args) => {
        // Normalize to forward slashes for internal join logic, or keep native?
        // Let's normalize to / for consistency unless user requests native path separator
        return args
            .map((part, i) => {
                if (!part) return '';
                // Replace backslashes with forward slashes for easier joining
                let p = part.replace(/\\/g, '/');
                if (i === 0) return p.trim().replace(/[\/]*$/g, '');
                return p.trim().replace(/(^[\/]*|[\/]*$)/g, '');
            })
            .filter(x => x.length)
            .join('/');
    },
    resolve: (...args) => {
        let resolved = '';
        for (let arg of args) {
            resolved = path.join(resolved, arg);
        }
        if (!resolved.startsWith('/')) {
            // If windows, check for drive letter C:\ or D:\ or start with \
            const isWindowsAbs = /^[a-zA-Z]:\\/.test(resolved) || resolved.startsWith('\\');
            if (!isWindowsAbs && native_path_cwd) {
                // native_path_cwd returns result of std::env::current_dir()
                const cwd = native_path_cwd();
                if (cwd) {
                    resolved = path.join(cwd, resolved);
                }
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
        encode: (str) => btoa(str), // Boa supports btoa/atob
        decode: (str) => atob(str),
    },
    compare: (a, b) => {
        if (a.length !== b.length) return false;
        // Constant time comparison not guaranteed here in JS easily without specialized tricks
        let mismatch = 0;
        for (let i = 0; i < a.length; ++i) {
            mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
        }
        return mismatch === 0;
    }
};

// --- OS ---
const os = {
    platform: () => {
        if (!native_os_info) return "unknown";
        const info = JSON.parse(native_os_info());
        return info.platform;
    },
    cpus: () => {
        if (!native_os_info) return 1;
        const info = JSON.parse(native_os_info());
        return info.cpus;
    },
    totalMemory: () => {
        if (!native_os_info) return 0;
        const info = JSON.parse(native_os_info());
        return info.totalMemory;
    },
    freeMemory: () => {
        if (!native_os_info) return 0;
        const info = JSON.parse(native_os_info());
        return info.freeMemory;
    },
    tmpdir: () => '/tmp' // Default for now, generic
};

// --- Net ---
const net = {
    resolveDNS: (hostname) => {
        if (!native_net_resolve) return [];
        return JSON.parse(native_net_resolve(hostname));
    },
    ip: () => native_net_ip ? native_net_ip() : "127.0.0.1",
    ping: (host) => {
        // Mock ping or simple verify
        return true;
    }
};

// --- Proc ---
// Memoize static info if needed, but here we call native
const proc = {
    pid: () => {
        if (!native_proc_info) return 0;
        const info = JSON.parse(native_proc_info());
        return info.pid;
    },
    uptime: () => {
        if (!native_proc_info) return 0;
        const info = JSON.parse(native_proc_info());
        return info.uptime;
    },
    memory: () => {
        // Optional: return full memory usage if possible
        return {};
    }
};

// --- Time ---
const time = {
    sleep: (ms) => {
        if (native_time_sleep) {
            native_time_sleep(ms);
        } else {
            console.log("[TitanCore] Warn: native_time_sleep missing");
        }
    },
    now: () => Date.now(),
    timestamp: () => new Date().toISOString()
};

// --- URL ---
// Simple URLSearchParams polyfill for V8 runtime
class TitanURLSearchParams {
    constructor(init = '') {
        this._params = {};
        if (typeof init === 'string') {
            const query = init.startsWith('?') ? init.slice(1) : init;
            query.split('&').forEach(pair => {
                const [key, value] = pair.split('=').map(decodeURIComponent);
                if (key) this._params[key] = value || '';
            });
        } else if (typeof init === 'object') {
            Object.assign(this._params, init);
        }
    }
    get(key) { return this._params[key] || null; }
    set(key, value) { this._params[key] = String(value); }
    has(key) { return key in this._params; }
    delete(key) { delete this._params[key]; }
    toString() {
        return Object.entries(this._params)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');
    }
    entries() { return Object.entries(this._params); }
    keys() { return Object.keys(this._params); }
    values() { return Object.values(this._params); }
}

const url = {
    parse: (str) => {
        // Basic URL parsing if native URL is available
        if (typeof URL !== 'undefined') {
            return new URL(str);
        }
        // Simple fallback parser
        const match = str.match(/^(https?:)\/\/([^/:]+)(?::(\d+))?(\/[^?#]*)?(\?[^#]*)?(#.*)?$/);
        if (!match) throw new Error('Invalid URL');
        return {
            protocol: match[1],
            hostname: match[2],
            port: match[3] || '',
            pathname: match[4] || '/',
            search: match[5] || '',
            hash: match[6] || ''
        };
    },
    format: (obj) => obj.toString ? obj.toString() : String(obj),
    SearchParams: TitanURLSearchParams
};


// Create the main core export object (following titan-valid pattern)
const core = {
    fs,
    path,
    crypto,
    os,
    net,
    proc,
    time,
    url
};


t.fs = fs;
t.path = path;
t.crypto = crypto;
t.os = os;
t.net = net;
t.proc = proc;
t.time = time;
t.url = url;

// Attach core as unified namespace (main access point)
t.core = core;

// Register as extension under multiple names for compatibility
t["titan-core"] = core;
t["@titanpl/core"] = core;

// Also register in t.exts
if (!t.exts) t.exts = {};
t.exts["titan-core"] = core;
t.exts["@titanpl/core"] = core;