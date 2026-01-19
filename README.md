# @titanpl/core
The official Core Standard Library for Titan Planet - a high-performance JavaScript runtime extension.

## Overview
`@titanpl/core` provides essential standard library modules for Titan applications, bridging high-performance Rust native implementations with an easy-to-use JavaScript API.

## Installation
```bash
npm install @titanpl/core
```

## Usage
The extension automatically attaches to the Titan runtime. You can access it via `t.core` or the `t` global object alias.

```javascript
// Access via t.core (Recommended)
const { fs, crypto, os } = t.core;

// Read a file
const content = fs.readFile("config.json");

// Generate UUID
const id = crypto.uuid();
```

## API Reference

### `fs` (File System)
Perform synchronous file system operations.
- `fs.readFile(path: string): string` - Read file content as UTF-8 string.
- `fs.writeFile(path: string, content: string): void` - Write string content to file.
- `fs.exists(path: string): boolean` - Check if path exists.
- `fs.mkdir(path: string): void` - Create a directory (recursive).
- `fs.remove(path: string): void` - Remove file or directory.
- `fs.readdir(path: string): string[]` - List directory contents.
- `fs.stat(path: string): object` - Get file statistics (`{ type: "file"|"directory", size: number }`).

### `path` (Path Manipulation)
Utilities for handling file paths.
- `path.join(...parts: string[]): string` - Join path segments.
- `path.resolve(...parts: string[]): string` - Resolve path to absolute.
- `path.dirname(path: string): string` - Get directory name.
- `path.basename(path: string): string` - Get base file name.
- `path.extname(path: string): string` - Get file extension.

### `crypto` (Cryptography)
Cryptographic utilities using native Rust implementations.
- `crypto.hash(algo: string, data: string): string` - Hash data. Supported algos: `sha256`, `sha512`, `md5`.
- `crypto.randomBytes(size: number): string` - Generate random bytes as hex string.
- `crypto.uuid(): string` - Generate a UUID v4.
- `crypto.compare(hash: string, target: string): boolean` - Constant-time comparison.

**Example:**
```javascript
const hash = t.core.crypto.hash("sha256", "hii");
const valid = t.core.crypto.compare(
    "a1a3b09875f9e9acade5623e1cca680009a6c9e0452489931cfa5b0041f4d290", 
    hash
);
```

### `os` (Operating System)
Get system information.
- `os.platform(): string` - OS platform (e.g., `linux`, `windows`).
- `os.cpus(): number` - Number of CPU cores.
- `os.totalMemory(): number` - Total system memory in bytes.
- `os.freeMemory(): number` - Free system memory in bytes.
- `os.tmpdir(): string` - Temporary directory path.

### `net` (Network)
Network utilities.
- `net.resolveDNS(hostname: string): string[]` - Resolve hostname to IP addresses.
- `net.ip(): string` - Get local IP address.

### `proc` (Process)
Current process information.
- `proc.pid(): number` - Process ID.
- `proc.uptime(): number` - System uptime in seconds.

### `time` (Time)
Time utilities.
- `time.sleep(ms: number): void` - Sleep for specified milliseconds.
- `time.now(): number` - Current timestamp (ms).
- `time.timestamp(): string` - Current ISO timestamp.

### `url` (URL)
URL parsing and manipulation.
- `url.parse(urlString: string): URLObject` - Parse URL string.
- `url.format(urlObject: object): string` - Format URL object.
- `new url.SearchParams(query: string|object)` - Handle query strings.

## Native Bindings
This extension includes native Rust bindings for high-performance operations. The native library is automatically loaded by the Titan Runtime.

