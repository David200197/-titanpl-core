// Type definitions for @titanpl/core
// This file facilitates type inference when this extension is installed in a Titan project.

declare global {
    namespace Titan {
        interface Runtime {
            /**
             * @titanpl/core Extension - Titan Core Standard Library
             */
            "@titanpl/core": TitanCore.Core;

            /**
             * Alias for @titanpl/core
             */
            "titan-core": TitanCore.Core;

            /** File System module */
            fs: TitanCore.FileSystem;
            /** Path manipulation module */
            path: TitanCore.Path;
            /** Cryptography module */
            crypto: TitanCore.Crypto;
            /** Operating System module */
            os: TitanCore.OS;
            /** Network module */
            net: TitanCore.Net;
            /** Process module */
            proc: TitanCore.Process;
            /** Time module */
            time: TitanCore.Time;
            /** URL module */
            url: TitanCore.URLModule;
            /** Buffer utility module */
            buffer: TitanCore.BufferModule;
            /** Local Storage module */
            ls: TitanCore.LocalStorage;
            /** Local Storage alias */
            localStorage: TitanCore.LocalStorage;
            /** Session management */
            session: TitanCore.Session;
            /** Cookie utilities */
            cookies: TitanCore.Cookies;
            /** Core namespace alias */
            core: TitanCore.Core;
        }
    }

    /**
     * Titan Core Global Namespace
     */
    namespace TitanCore {
        interface Core {
            fs: FileSystem;
            path: Path;
            crypto: Crypto;
            os: OS;
            net: Net;
            proc: Process;
            time: Time;
            url: URLModule;
            buffer: BufferModule;
            ls: LocalStorage;
            session: Session;
            cookies: Cookies;
        }

        // --- File System ---
        interface FileSystem {
            /** Reads file content as UTF-8 string */
            readFile(path: string): string;
            /** Writes content to file */
            writeFile(path: string, content: string): void;
            /** Reads directory contents */
            readdir(path: string): string[];
            /** Creates directory recursively */
            mkdir(path: string): void;
            /** Checks if path exists */
            exists(path: string): boolean;
            /** Returns file stats */
            stat(path: string): Stats;
            /** Removes file or directory */
            remove(path: string): void;
        }

        interface Stats {
            size: number;
            isFile: boolean;
            isDir: boolean;
            modified: number;
        }

        // --- Path ---
        interface Path {
            /** Joins path segments */
            join(...args: string[]): string;
            /** Resolves path segments to an absolute path */
            resolve(...args: string[]): string;
            /** Returns the extension of the path */
            extname(path: string): string;
            /** Returns the directory name of a path */
            dirname(path: string): string;
            /** Returns the last portion of a path */
            basename(path: string): string;
        }

        // --- Crypto ---
        interface Crypto {
            /** Computes hash of data using specified algorithm (e.g., 'sha256', 'sha512') */
            hash(algorithm: string, data: string): string;
            /** Generates random bytes as a hex string */
            randomBytes(size: number): string;
            /** Generates a UUID v4 string */
            uuid(): string;
            base64: {
                encode(str: string): string;
                decode(str: string): string;
            };
            /** Encrypts data using AES-256-GCM. Returns Base64 string. */
            encrypt(algorithm: string, key: string, plaintext: string): string;
            /** Decrypts data using AES-256-GCM. Returns plaintext string. */
            decrypt(algorithm: string, key: string, ciphertext: string): string;
            /** Computes HMAC-SHA256/512. Returns Hex string. */
            hashKeyed(algorithm: string, key: string, message: string): string;
            /** Constant-time string comparison */
            compare(a: string, b: string): boolean;
        }

        // --- OS ---
        interface OS {
            /** Returns the operating system platform */
            platform(): string;
            /** Returns the number of logical CPUs */
            cpus(): number;
            /** Returns total system memory in bytes */
            totalMemory(): number;
            /** Returns free system memory in bytes */
            freeMemory(): number;
            /** Returns the system temporary directory */
            tmpdir(): string;
        }

        // --- Net ---
        interface Net {
            /** Resolves hostname to IP addresses */
            resolveDNS(hostname: string): string[];
            /** Returns the local machine's IP address */
            ip(): string;
            /** Pings a host (mock implementation always returns true) */
            ping(host: string): boolean;
        }

        // --- Process ---
        interface Process {
            /** Returns the current process ID */
            pid(): number;
            /** Returns the process uptime in seconds */
            uptime(): number;
            /** Returns memory usage statistics */
            memory(): Record<string, any>;
        }

        // --- Time ---
        interface Time {
            /** Pauses execution for the specified number of milliseconds */
            sleep(ms: number): void;
            /** Returns the number of milliseconds elapsed since the epoch */
            now(): number;
            /** Returns the current time as an ISO string */
            timestamp(): string;
        }

        // --- URL ---
        interface URLModule {
            /** Parses a URL string */
            parse(url: string): UrlObject;
            /** Formats a URL object into a string */
            format(urlObj: any): string;
            /** URLSearchParams constructor */
            SearchParams: typeof TitanURLSearchParams;
        }

        interface UrlObject {
            protocol: string;
            hostname: string;
            port: string;
            pathname: string;
            search: string;
            hash: string;
        }

        class TitanURLSearchParams {
            constructor(init?: string | Record<string, string>);
            get(key: string): string | null;
            set(key: string, value: string): void;
            has(key: string): boolean;
            delete(key: string): void;
            toString(): string;
            entries(): [string, string][];
            keys(): string[];
            values(): string[];
        }

        // --- Buffer ---
        interface BufferModule {
            /** Creates Uint8Array from Base64 string */
            fromBase64(str: string): Uint8Array;
            /** Encodes Uint8Array or String to Base64 string */
            toBase64(bytes: Uint8Array | string): string;
            /** Creates Uint8Array from Hex string */
            fromHex(str: string): Uint8Array;
            /** Encodes bytes to Hex string */
            toHex(bytes: Uint8Array | string): string;
            /** Creates Uint8Array from UTF-8 string */
            fromUtf8(str: string): Uint8Array;
            /** Decodes bytes to UTF-8 string */
            toUtf8(bytes: Uint8Array): string;
        }

        // --- Local Storage ---
        interface LocalStorage {
            /** Gets a value from local storage */
            get(key: string): string | null;
            /** Sets a value in local storage */
            set(key: string, value: string): void;
            /** Removes a value from local storage */
            remove(key: string): void;
            /** Clears all local storage */
            clear(): void;
            /** Returns all keys in local storage */
            keys(): string[];
        }

        // --- Session ---
        interface Session {
            /** Gets a value from a session */
            get(sessionId: string, key: string): string | null;
            /** Sets a value in a session */
            set(sessionId: string, key: string, value: string): void;
            /** Deletes a value from a session */
            delete(sessionId: string, key: string): void;
            /** Clears a session */
            clear(sessionId: string): void;
        }

        // --- Cookies ---
        interface Cookies {
            /** Parses cookie from request headers */
            get(req: any, name: string): string | null;
            /** Sets Set-Cookie header on response */
            set(res: any, name: string, value: string, options?: CookieOptions): void;
            /** Deletes cookie by setting maxAge=0 */
            delete(res: any, name: string): void;
        }

        interface CookieOptions {
            maxAge?: number;
            path?: string;
            httpOnly?: boolean;
            secure?: boolean;
            sameSite?: string;
        }
    }
}

export { };
