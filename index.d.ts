// Type definitions for @titanpl/core
// Project: https://github.com/titanpl/core
// Definitions by: TitanPL Team
//
// This reference ensures global types (t.fs, t.response, etc.) are always
// loaded when this package is imported OR included via tsconfig "types".
/// <reference path="./global.d.ts" />

// ==================== ESM Named Exports ====================
// These match the `export { ... }` block in the JS implementation.
// Usage: import { fs, crypto, path } from '@titanpl/core';

/** File System module */
export declare const fs: TitanCore.FileSystem;

/** Path manipulation module */
export declare const path: TitanCore.Path;

/** Cryptography module */
export declare const crypto: TitanCore.Crypto;

/** Operating System module */
export declare const os: TitanCore.OS;

/** Network module */
export declare const net: TitanCore.Net;

/** Process module */
export declare const proc: TitanCore.Process;

/** Time module */
export declare const time: TitanCore.Time;

/** URL module */
export declare const url: TitanCore.URLModule;

/** Buffer module */
export declare const buffer: TitanCore.BufferModule;

/** Local Storage module */
export declare const ls: TitanCore.LocalStorage;

/** Session module */
export declare const session: TitanCore.Session;

/** Cookies module */
export declare const cookies: TitanCore.Cookies;

/** Response builder module */
export declare const response: TitanCore.ResponseModule;

/** URLSearchParams class */
export declare class TitanURLSearchParams extends TitanCore.TitanURLSearchParams {}

// ==================== Utility Functions ====================

/**
 * Base64 encode a string (polyfill for btoa).
 * @param input String to encode.
 * @returns Base64 encoded string.
 */
export declare function local_btoa(input: string): string;

/**
 * Base64 decode a string (polyfill for atob).
 * @param input Base64 string to decode.
 * @returns Decoded string.
 */
export declare function local_atob(input: string): string;

/**
 * Encode a string to UTF-8 bytes.
 * @param str String to encode.
 * @returns UTF-8 byte array.
 */
export declare function local_utf8_encode(str: string): Uint8Array;

/**
 * Decode UTF-8 bytes to a string.
 * @param bytes UTF-8 byte array.
 * @returns Decoded string.
 */
export declare function local_utf8_decode(bytes: Uint8Array): string;

/**
 * Convert a hex string to a Uint8Array.
 * @param hex Hex string (e.g., "48656c6c6f").
 * @returns Byte array.
 */
export declare function hexToBytes(hex: string): Uint8Array;

/**
 * Convert a Uint8Array to a hex string.
 * @param bytes Byte array.
 * @returns Hex string.
 */
export declare function bytesToHex(bytes: Uint8Array): string;