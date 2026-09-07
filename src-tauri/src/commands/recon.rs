
use crate::error::AppError;

#[tauri::command]
pub fn scan_port(host: String, port: u16) -> Result<String, AppError> {
    Err(AppError::new("RECON toolkit not yet implemented in desktop build"))
}