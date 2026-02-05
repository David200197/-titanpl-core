# Post-Fix Analysis: Core Extension Initialization

## Problem Summary
The user encountered an issue where `t.ls` (Local Storage) was `undefined` in the runtime, causing the error:
`Cannot read properties of undefined (reading 'set')`

### Root Causes
1.  **Improper Global Attachment**: The initialization logic in `index.js` and `bootstrap.js` was too defensive. It would skip attaching APIs if `t[key]` (like `t.ls`) already existed, even if it was just a placeholder or `null`.
2.  **Runtime vs. Module Context**: `titan.json` was pointing to `index.js` as the `main` entry point. However, `index.js` is an ESM module (using `export`). The Titan runtime (`server/src/extensions/external.rs`) wraps the extension code in a function `(function(t) { ... })`, which causes a syntax error if `export` statements are present inside. This meant the extension wasn't running at all, or failing silently/catastrophically during load.

## The Fixes

### 1. Robust Attachment Logic
We simplified the module attachment logic in both `index.js` and `bootstrap.js` to ensure that native bindings are preserved while JS wrappers are reliably attached.

**Old Logic:**
*Complexe `Reflect.defineProperty` loop that tried to be too smart and often failed silently.*

**New Logic:**
```javascript
// A. Inject into the Extension Namespace (Preserving existing Natives!)
if (t[EXT_KEY]) {
    Object.assign(t[EXT_KEY], API);
} else {
    t[EXT_KEY] = API;
}

// B. Inject into t.core
if (!t.core) t.core = {};
Object.assign(t.core, API);

// C. Shortcuts (t.fs, t.ls, etc.)
Object.keys(API).forEach(key => {
    // ...
    if (t[key] && typeof t[key] === 'object' && typeof val === 'object') {
        Object.assign(t[key], val); // Merge
    } else {
        t[key] = val; // Overwrite
    }
});
```

### 2. Entry Point Switch
We changed the `main` field in `titan.json` to point to `bootstrap.js` instead of `index.js`.

**`bootstrap.js` vs `index.js`:**
*   **`index.js`**: Reference implementation for bundlers (Vite/Rolldown). Contains `export` statements. Good for compile-time usage but bad for runtime injection.
*   **`bootstrap.js`**: Specific runtime initialization script. No `export` statements. Wraps logic in an IIFE. Designed specifically to be loaded by the Titan runtime's `external.rs`.

### 3. Log Cleanup
Removed verbose "Extension loading..." and "Extension loaded!" logs from both files to reduce console noise, as requested.

## Verification
A test action `test_ls.js` was created to verify `t.ls` availability.
Response: `{"status": "ok", "value": "success", "type": "object"}` confirms the fix.
