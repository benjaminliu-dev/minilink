use sqlite::State;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast};
use tokio_native_tls::native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector};
use chrono::{Utc};
// TODO: Replace is_radio with device_type (1: WiFi, 2: Radio, 3: Bluetooth)
// TODO: Implement user logic for alternate device types using prefixes
pub struct MinilinkServerHandler {
    pub address: String,
    pub blocked_addresses: Vec<String>,
    pub cert: Identity,
    pub der_path: String,
    pub logfile_path: String,
    pub log: bool,
    pub tcp_listener: TcpListener,
    pub connected_addresses: Arc<Mutex<Vec<String>>>,
    pub users_db_path: String,
}

fn log(message: String, address: &str, name: Option<&str>) -> String {
    let time = Utc::now();
    if name.is_none() {
        return format!("[{time}]: {address}: {message}\n");
    } else {
        return format!("[{time}]: {address}:{}: {message}\n", name.unwrap());
    }
}
impl MinilinkServerHandler {
    pub async fn new(
        address: String,
        blocked_addresses: Vec<String>,
        p12_path: String,
        der_path: String,
        logfile_path: String,
        log: bool,
        password: String,
        users_db_path: String,
    ) -> Self {
        let der = std::fs::read(&p12_path).unwrap();
        let certificate = Identity::from_pkcs12(der.as_slice(), &password).unwrap();

        let tcp_listener = TcpListener::bind(&address).await.unwrap();

        if log {
            fs::write(&logfile_path, "MinilinkServer created\n").unwrap();
        }

        MinilinkServerHandler {
            address,
            blocked_addresses,
            cert: certificate,
            der_path,
            logfile_path,
            log,
            tcp_listener,
            connected_addresses: Arc::new(Mutex::new(Vec::new())),
            users_db_path,
        }
    }

    pub async fn start(&self) {
        fs::write(&self.logfile_path, "MinilinkServer started\n").unwrap();

        let tls_acceptor = tokio_native_tls::TlsAcceptor::from(
            TlsAcceptor::builder(self.cert.clone()).build().unwrap(),
        );
        let (tx, _rx) = broadcast::channel::<String>(256);

        // let connected_addresses = Arc::clone(&self.connected_addresses);
        // // let console_connected_addresses = Arc::clone(&connected_addresses);
        // let names = Arc::new(Mutex::new(HashMap::<String, String>::new()));
        // let names_for_console = Arc::clone(&names);
        let logfile_path_for_console = self.logfile_path.clone();
        let db_path_for_console = self.users_db_path.clone();

        let db_connection = Arc::new(Mutex::new(
            sqlite::Connection::open(&db_path_for_console).expect("Failed to open database"),
        ));

        // Clone for console task
        let db_connection_console = Arc::clone(&db_connection);

        let start_query = "

            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;


            CREATE TABLE IF NOT EXISTS users (
                username TEXT NOT NULL UNIQUE,
                address TEXT NOT NULL UNIQUE,
                is_radio BOOL NOT NULL DEFAULT 0
            );
            DELETE FROM users;
        ";

        db_connection
            .lock()
            .await
            .execute(start_query)
            .expect("Failed to create users table");

        tokio::spawn(async move {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin).lines();

            println!("Server console initialized. Type commands here:");

            while let Ok(Some(line)) = reader.next_line().await {
                let command = line.trim();
                match command {
                    "status" => println!("Server ok"),
                    "connections" => {
                        let guard = db_connection_console.lock().await;
                        let mut statement = guard
                            .prepare("SELECT username, address, is_radio FROM users")
                            .expect("Failed to prepare statement");

                        while let Ok(State::Row) = statement.next() {
                            let username: String = statement.read(0).unwrap();
                            let address: String = statement.read(1).unwrap();
                            let is_radio: i64 = statement.read(2).unwrap();

                            println!(
                                "Username: {}, Address: {}, Is Radio: {}",
                                username, address, is_radio
                            );
                        }
                    }
                    "exit" => {
                        println!("Shutting down server...");
                        std::process::exit(0);
                    }

                    "help" => {
                        println!("Available commands:");
                        println!("status - Check server status");
                        println!("connections - List connected clients");
                        println!("exit - Shut down the server");
                        println!("help - Show this help message");
                        println!("save_log - Save the current log to saved.log");
                    }

                    "save_log" => {
                        let src = logfile_path_for_console.clone();
                        tokio::spawn(async move {
                            let _ = tokio::fs::copy(src, "saved.log").await;
                            println!("Log saved to saved.log");
                        });
                    }

                    _ => println!("Unknown command: {}", command),
                }
            }
        });

        loop {
            let logfile_path_clone = self.logfile_path.clone();
            let should_log = self.log;
            let (sock, remote_addr) = self.tcp_listener.accept().await.unwrap();
            let tls_acceptor = tls_acceptor.clone();
            let broadcast_tx = tx.clone();
            let mut client_rx = broadcast_tx.subscribe();
            let client_id = remote_addr.to_string();
            let db_connection_client = Arc::clone(&db_connection);
            // Log incoming connection asynchronously before spawning the client task
            if should_log {
                if let Ok(mut file) = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&self.logfile_path)
                    .await
                {
                    let _ = file
                        .write_all(
                            log(
                                format!("Accepted connection from {remote_addr}"),
                                &remote_addr.to_string(),
                                None,
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            }

            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(sock).await {
                    Ok(s) => {
                        db_connection_client.lock().await.execute(
                            format!("INSERT OR IGNORE INTO users (username, address) VALUES ('{}', '{}')", client_id, remote_addr.to_string()).as_str()
                        ).expect("Failed to insert user into database");
                        if let Ok(mut file) = OpenOptions::new()
                            .append(true)
                            .open(&logfile_path_clone)
                            .await
                        {
                            let _ = file
                                .write_all(
                                    log(
                                        format!("Mututal TLS Handshake successful with {remote_addr}"),
                                        &remote_addr.to_string(),
                                        None,
                                    )
                                    .as_bytes(),
                                )
                                .await;
                        }
                        s
                    }
                    Err(_) => {
                        if should_log {
                            if let Ok(mut file) = OpenOptions::new()
                                .append(true)
                                .open(&logfile_path_clone)
                                .await
                            {
                                let _ = file
                                    .write_all(
                                        log(
                                            format!("TLS Accept error from {remote_addr}"),
                                            &remote_addr.to_string(),
                                            None,
                                        )
                                        .as_bytes(),
                                    )
                                    .await;
                            }
                        }
                        return;
                    }
                };

                let (mut reader, mut writer) = tokio::io::split(tls_stream);
                let mut buffer = [0; 1024];
                loop {
                    tokio::select! {
                        // Event A: Client sends data
                        read_result = reader.read(&mut buffer) => {
                            match read_result {
                                Ok(0) => {
                                    let client_name = {
                                        let guard = db_connection_client.lock().await;
                                        let mut statement = guard.prepare(format!("SELECT username FROM users WHERE address = '{}'", remote_addr.to_string())).expect("Failed to prepare statement");
                                        let mut username = String::new();

                                        while let Ok(State::Row) = statement.next() {
                                            username = statement.read::<String, _>(0).unwrap();
                                        }

                                        username
                                    };

                                    // Log clean disconnection
                                    if should_log {
                                        if let Ok(mut file) = OpenOptions::new().append(true).open(&logfile_path_clone).await {
                                            let _ = file.write_all(log(format!("Client {remote_addr} disconnected"), &remote_addr.to_string(), Some(&client_name)).as_bytes()).await;
                                        }
                                    }

                                    {
                                        let guard = db_connection_client.lock().await;
                                        guard.execute(format!("DELETE FROM users WHERE address = '{}'", remote_addr.to_string()).as_str()).expect("Failed to delete user from database");
                                    }
                                    return;
                                }
                                Ok(n) => {
                                    let received = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

                                    if let Some(name) = received.strip_prefix("setname ") {
                                        let name_trimmed = name.trim();
                                        let guard = db_connection_client.lock().await;
                                        guard.execute(
                                            format!("UPDATE users SET username = '{}' WHERE address = '{}'", name_trimmed, remote_addr.to_string()).as_str()
                                        ).expect("Failed to update username in database");
                                        let _ = writer.write_all(format!("Name set to {}\n", name_trimmed).as_bytes()).await;
                                        continue;
                                    }

                                    if let Some(is_radio_str) = received.strip_prefix("setradio ") {
                                        let is_radio_value = match is_radio_str.trim() {
                                            "true" => 1,
                                            "false" => 0,
                                            _ => {
                                                let _ = writer.write_all(b"Invalid value for setradio. Use 'true' or 'false'.\n").await;
                                                continue;
                                            }
                                        };
                                        let guard = db_connection_client.lock().await;
                                        guard.execute(
                                            format!("UPDATE users SET is_radio = {} WHERE address = '{}'", is_radio_value, remote_addr.to_string()).as_str()
                                        ).expect("Failed to update is_radio in database");
                                        let _ = writer.write_all(format!("is_radio set to {}\n", is_radio_value == 1).as_bytes()).await;
                                        continue;
                                    }

                                    let client_name = {
                                        let guard = db_connection_client.lock().await;
                                        let mut statement = guard.prepare(format!("SELECT username FROM users WHERE address = '{}'", remote_addr.to_string())).expect("Failed to prepare statement");
                                        let mut username = String::new();

                                        while let Ok(State::Row) = statement.next() {
                                            username = statement.read::<String, _>(0).unwrap();
                                        }

                                        username
                                    };

                                    let broadcast_message = format!("{client_id}\t{received}");
                                    let _ = broadcast_tx.send(broadcast_message);
                                    // Log the data received from the client
                                    if should_log {
                                        if let Ok(mut file) = OpenOptions::new().append(true).open(&logfile_path_clone).await {
                                            let _ = file.write_all(log(received.clone(), &remote_addr.to_string(), Some(&client_name)).as_bytes()).await;
                                        }
                                    }
                                }
                                Err(_) => {
                                    let guard = db_connection_client.lock().await;
                                    guard.execute(format!("DELETE FROM users WHERE address = '{}'", remote_addr.to_string()).as_str()).expect("Failed to delete user from database");
                                    return;
                                }
                            }
                        }

                        // Event B: Server broadcasts incoming client data to this client

                        broadcast_result = client_rx.recv() => {
                            if let Ok(msg) = broadcast_result {
                                if let Some((sender, payload)) = msg.split_once('\t') {
                                    if sender == client_id {
                                        continue;
                                    }
                                    let sender_name = {
                                        let guard = db_connection_client.lock().await;
                                        let mut statement = guard.prepare(format!("SELECT username FROM users WHERE address = '{}'", sender)).expect("Failed to prepare statement");
                                        let mut username = sender.to_string();

                                        while let Ok(State::Row) = statement.next() {
                                            username = statement.read::<String, _>(0).unwrap();
                                        }

                                        username
                                    };
                                    let forwarded = format!("{sender_name}: {payload}\n");
                                    if writer.write_all(forwarded.as_bytes()).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}

pub struct MinilinkClientHandler {
    pub server_address: String,
    pub server_domain: String,
    pub client_cert: Identity,
    pub server_ca_path: String,
    pub entry_message: String,
    pub is_radio: bool,
}

impl MinilinkClientHandler {
    pub async fn new(
        server_address: String,
        server_domain: String,
        client_p12_path: String,
        server_ca_path: String,
        password: String,
        entry_message: String,
        is_radio: bool,
    ) -> Self {
        let p12_der = fs::read(&client_p12_path).expect("Failed to read client .p12 file");
        let client_cert =
            Identity::from_pkcs12(&p12_der, &password).expect("Failed to parse client identity");

        MinilinkClientHandler {
            server_address,
            server_domain,
            client_cert,
            server_ca_path,
            entry_message,
            is_radio,
        }
    }

    pub async fn start(&self) {
        println!("Connecting to server at {}...", self.server_address);

        let ca_der = fs::read(&self.server_ca_path).expect("Failed to read server CA file");
        let server_ca =
            Certificate::from_der(&ca_der).expect("Failed to parse server CA certificate");

        let mut connector_builder = TlsConnector::builder();
        connector_builder
            .identity(self.client_cert.clone())
            .add_root_certificate(server_ca)
            .danger_accept_invalid_certs(true);

        let native_connector = connector_builder.build().unwrap();
        let tls_connector = tokio_native_tls::TlsConnector::from(native_connector);

        let tcp_stream = TcpStream::connect(&self.server_address).await.unwrap();

        let mut tls_stream = tls_connector
            .connect(&self.server_domain, tcp_stream)
            .await
            .unwrap();
        println!("Mutual TLS Handshake successful!");

        tls_stream
            .write_all(self.entry_message.as_bytes())
            .await
            .unwrap();
        tls_stream.flush().await.unwrap();

        let (mut reader, mut writer) = io::split(tls_stream);

        tokio::spawn(async move {
            let mut buffer = [0; 1024];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => {
                        println!("\nServer closed the connection.");
                        std::process::exit(0);
                    }
                    Ok(n) => {
                        let msg = String::from_utf8_lossy(&buffer[..n]);
                        print!("{}", msg);
                        print!("msg> ");
                        let _ = std::io::stdout().flush();
                    }
                    Err(e) => {
                        println!("\nError reading from server: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        });

        let stdin = io::stdin();
        let mut stdin_reader = BufReader::new(stdin).lines();
        println!("Authenticated successfully. Type messages below to log to the server:");

        while let Ok(Some(line)) = stdin_reader.next_line().await {
            print!("msg> ");
            let _ = std::io::stdout().flush();

            let mut payload = line.trim().to_string();
            payload.push('\n');

            if writer.write_all(payload.as_bytes()).await.is_err() {
                println!("Failed to send data to server. Connection dropped.");
                break;
            }
        }
    }
}
