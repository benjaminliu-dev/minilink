pub mod network;

use crate::network::{MinilinkClientHandler, MinilinkServerHandler};
use serde_json::Value;
use std::env;
use std::fs;

// Replace your main function block in src/main.rs with this:
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Usage: minilink <cfg_path> <der_path> <pkcs12_path>");
        return;
    }

    let cfg_path: String = args.get(1).unwrap().to_string();
    let der_path: String = args.get(2).unwrap().to_string();
    let pkcs12_path: String = args.get(3).unwrap().to_string();

    let contents = fs::read_to_string(cfg_path).expect("Something went wrong reading the file");
    let v: Value = serde_json::from_str(contents.as_str()).unwrap();

    let is_server: bool = match v["mode"].as_str() {
        Some("server") => true,
        Some("client") => false,
        _ => false,
    };

    let address: String = v["address"].to_string().replace('"', ""); // Removes quotes from JSON string strings
    let mut blocked_addresses: Vec<String> = vec![];
    if let Some(blocked_addrs) = v["blocked_addresses"].as_array() {
        for address in blocked_addrs {
            blocked_addresses.push(address.to_string());
        }
    }

    let logfile_path: String = v["logfile_path"].to_string().replace('"', "");
    let log: bool = v["log"].as_bool().unwrap_or(true);
    let domain = v["domain"].to_string().replace('"', "");

    // Extract the password from configuration. Fallback to empty string if missing.
    let password = v["password"].as_str().unwrap_or("").to_string();

    if is_server {
        // Added password parameter
        let server: MinilinkServerHandler = MinilinkServerHandler::new(
            address,
            blocked_addresses,
            pkcs12_path,
            der_path,
            logfile_path,
            log,
            password,
        )
        .await;
        server.start().await;
    } else {
        let entry_message: String = v["entry_message"].to_string();
        // Added password parameter
        let client: MinilinkClientHandler = MinilinkClientHandler::new(
            address,
            domain,
            pkcs12_path,
            der_path,
            password,
            entry_message,
        )
        .await;
        client.start().await;
    }
}
