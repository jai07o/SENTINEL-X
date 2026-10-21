#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DesktopConfig {
    pub backend_url: String,
    pub auto_connect: bool,
    pub notifications_enabled: bool,
    pub version: String,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            backend_url: "http://127.0.0.1:8000".to_string(),
            auto_connect: true,
            notifications_enabled: true,
            version: "0.1.0".to_string(),
        }
    }
}

pub struct AppState {
    pub config: Mutex<DesktopConfig>,
}

#[derive(Serialize)]
pub struct ConnectivityResult {
    pub connected: bool,
    pub status_code: u16,
    pub latency_ms: u64,
    pub details: String,
}

#[tauri::command]
fn get_desktop_config(state: tauri::State<AppState>) -> Result<DesktopConfig, String> {
    let conf = state.config.lock().map_err(|e| e.to_string())?;
    Ok(conf.clone())
}

#[tauri::command]
fn set_backend_url(url: String, state: tauri::State<AppState>) -> Result<DesktopConfig, String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Backend URL must begin with http:// or https://".to_string());
    }

    let mut conf = state.config.lock().map_err(|e| e.to_string())?;
    conf.backend_url = url.trim_end_matches('/').to_string();
    Ok(conf.clone())
}

#[tauri::command]
async fn check_backend_connectivity(state: tauri::State<'_, AppState>) -> Result<ConnectivityResult, String> {
    let url = {
        let conf = state.config.lock().map_err(|e| e.to_string())?;
        format!("{}/api/v1/health", conf.backend_url)
    };

    let start = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;

    match client.get(&url).send().await {
        Ok(resp) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status = resp.status().as_u16();
            let is_success = resp.status().is_success();
            let body = resp.text().await.unwrap_or_else(|_| "{}".to_string());

            Ok(ConnectivityResult {
                connected: is_success,
                status_code: status,
                latency_ms,
                details: body,
            })
        }
        Err(e) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            Ok(ConnectivityResult {
                connected: false,
                status_code: 0,
                latency_ms,
                details: format!("Connection failed: {}", e),
            })
        }
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            config: Mutex::new(DesktopConfig::default()),
        })
        .invoke_handler(tauri::generate_handler![
            get_desktop_config,
            set_backend_url,
            check_backend_connectivity
        ])
        .run(tauri::generate_context!())
        .expect("error while running SENTINEL-X desktop application");
}
