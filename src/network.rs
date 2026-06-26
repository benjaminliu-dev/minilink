use std::fs;
use std::time::Instant;
use tokio::fs::OpenOptions;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_native_tls::native_tls::{
    Certificate, Identity, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
};

pub struct MinilinkServerHandler {
    pub address: String,
    pub blocked_addresses: Vec<String>,
    pub cert: Identity,
    pub der_path: String,
    pub logfile_path: String,
    pub log: bool,
    pub tcp_listener: TcpListener,
    pub connected_addresses: Vec<String>,
}

fn log(message: String, instant: Instant) -> String {
    let elapsed = instant.elapsed().as_millis().to_string();
    format!("[{elapsed}]: {message}\n")
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
            connected_addresses: vec![],
        }
    }

    pub async fn start(&self) {
        fs::write(&self.logfile_path, "MinilinkServer started\n").unwrap();
        let start = Instant::now();
        let ca_der = std::fs::read(self.der_path.clone()).expect("Failed to read CA cert");
        let client_ca = Certificate::from_der(&ca_der).expect("Failed to parse CA cert");

        let tls_acceptor = tokio_native_tls::TlsAcceptor::from(
            TlsAcceptor::builder(self.cert.clone()).build().unwrap(),
        );
        let (tx, _rx) = broadcast::channel::<String>(16);

        let tx_clone = tx.clone();

        tokio::spawn(async {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin).lines();

            println!("Server console initialized. Type commands here:");

            while let Ok(Some(line)) = reader.next_line().await {
                let command = line.trim();
                match command {
                    "status" => println!("Server ok"),
                    "exit" => {
                        println!("Shutting down server...");
                        std::process::exit(0);
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
            let mut client_rx = tx.subscribe();

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
                            log(format!("Accepted connection from {remote_addr}"), start)
                                .as_bytes(),
                        )
                        .await;
                }
            }

            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(sock).await {
                    Ok(s) => s,
                    Err(_) => {
                        if should_log {
                            if let Ok(mut file) = OpenOptions::new()
                                .append(true)
                                .open(&logfile_path_clone)
                                .await
                            {
                                let _ = file
                                    .write_all(
                                        log(format!("TLS Accept error from {remote_addr}"), start)
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
                                    // Log clean disconnection
                                    if should_log {
                                        if let Ok(mut file) = OpenOptions::new().append(true).open(&logfile_path_clone).await {
                                            let _ = file.write_all(log(format!("Client {remote_addr} disconnected"), start).as_bytes()).await;
                                        }
                                    }
                                    return;
                                }
                                Ok(n) => {
                                    let received = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

                                    // Log the data received from the client
                                    if should_log {
                                        if let Ok(mut file) = OpenOptions::new().append(true).open(&logfile_path_clone).await {
                                            let _ = file.write_all(log(format!("Received from {remote_addr}: {received}"), start).as_bytes()).await;
                                        }
                                    }
                                }
                                Err(_) => return,
                            }
                        }

                        // Event B: Server broadcasts stdin data to this client
                        broadcast_result = client_rx.recv() => {
                            if let Ok(msg) = broadcast_result {
                                if writer.write_all(msg.as_bytes()).await.is_err() {
                                    return;
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
    pub entry_message: String
}

impl MinilinkClientHandler {
    pub async fn new(
        server_address: String,
        server_domain: String,
        client_p12_path: String,
        server_ca_path: String,
        password: String,
        entry_message: String
    ) -> Self {
        let p12_der = fs::read(&client_p12_path).expect("Failed to read client .p12 file");
        let client_cert =
            Identity::from_pkcs12(&p12_der, &password).expect("Failed to parse client identity");

        MinilinkClientHandler {
            server_address,
            server_domain,
            client_cert,
            server_ca_path,
            entry_message
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
            let mut payload = line.trim().to_string();
            payload.push('\n');

            if writer.write_all(payload.as_bytes()).await.is_err() {
                println!("Failed to send data to server. Connection dropped.");
                break;
            }
        }
    }
}
