use std::collections::HashMap;
use std::sync::RwLock;
use once_cell::sync::Lazy;

static STORAGE: Lazy<RwLock<HashMap<String, String>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

static SESSIONS: Lazy<RwLock<HashMap<String, String>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

// --- Local Storage ---

pub fn ls_get(key: &str) -> Option<String> {
    STORAGE.read().ok()?.get(key).cloned()
}

pub fn ls_set(key: &str, value: &str) -> Result<(), String> {
    STORAGE
        .write()
        .map_err(|_| "Storage lock poisoned".to_string())?
        .insert(key.to_string(), value.to_string());
    Ok(())
}

pub fn ls_remove(key: &str) -> Result<(), String> {
    STORAGE
        .write()
        .map_err(|_| "Storage lock poisoned".to_string())?
        .remove(key);
    Ok(())
}

pub fn ls_clear() -> Result<(), String> {
    STORAGE
        .write()
        .map_err(|_| "Storage lock poisoned".to_string())?
        .clear();
    Ok(())
}

pub fn ls_keys() -> Result<Vec<String>, String> {
    Ok(STORAGE
        .read()
        .map_err(|_| "Storage lock poisoned".to_string())?
        .keys()
        .cloned()
        .collect())
}

// --- Sessions ---

pub fn session_get(session_id: &str, key: &str) -> Option<String> {
    let comp_key = format!("{}:{}", session_id, key);
    SESSIONS.read().ok()?.get(&comp_key).cloned()
}

pub fn session_set(session_id: &str, key: &str, value: &str) -> Result<(), String> {
    let comp_key = format!("{}:{}", session_id, key);
    SESSIONS
        .write()
        .map_err(|_| "Session lock poisoned".to_string())?
        .insert(comp_key, value.to_string());
    Ok(())
}

pub fn session_delete(session_id: &str, key: &str) -> Result<(), String> {
    let comp_key = format!("{}:{}", session_id, key);
    SESSIONS
        .write()
        .map_err(|_| "Session lock poisoned".to_string())?
        .remove(&comp_key);
    Ok(())
}

pub fn session_clear(session_id: &str) -> Result<(), String> {
    let prefix = format!("{}:", session_id);
    SESSIONS
        .write()
        .map_err(|_| "Session lock poisoned".to_string())?
        .retain(|k, _| !k.starts_with(&prefix));
    Ok(())
}