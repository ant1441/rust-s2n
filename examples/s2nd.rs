extern crate s2n;

use std::net::TcpListener;

static CHAIN: &str = include_str!("chain.crt");
static PRIVATE_KEY: &str = include_str!("private.key");
static DHPARAMS: &str = include_str!("dhparams");

pub fn main() {
    let host = "127.0.0.1";
    let port = 8443;
    let cipher_preferences = "default";

    let mut config = s2n::Config::default();

    config
        .add_cert_chain_and_key(CHAIN, PRIVATE_KEY)
        .unwrap();
    config.add_dhparams(DHPARAMS).unwrap();
    config.set_cipher_preferences(cipher_preferences).unwrap();

    let mut connection: s2n::Connection = Default::default();

    connection.set_config(&config).unwrap();

    let listener = TcpListener::bind((host, port)).unwrap();
    println!("Listening on {}:{}", host, port);

    for stream in listener.incoming() {
        let stream = &stream.unwrap();
        connection.set_tcp_stream(stream).unwrap();

        println!("Negotiating!");
        connection.negotiate().unwrap();

        println!("Client hello version: {}",
                 connection.get_client_hello_version().unwrap());
        println!("Client protocol version: {}",
                 connection.get_client_protocol_version().unwrap());
        println!("Server protocol version: {}",
                 connection.get_server_protocol_version().unwrap());
        println!("Actual protocol version: {}",
                 connection.get_actual_protocol_version().unwrap());

        connection
            .get_server_name()
            .map(|n| println!("Server name: {}", n));
        connection
            .get_application_protocol()
            .map(|p| println!("Application protocol: {}", p));
        connection
            .get_curve()
            .map(|c| println!("Curve: {}", c.unwrap())).unwrap();
        connection
            .get_ocsp_response()
            .map(|r| println!("OCSP Response received: {:?}", r));
        connection
            .get_cipher()
            .map(|c| println!("Cipher negotiated: {:?}", c));

        echo(&mut connection).unwrap();

        connection.shutdown().unwrap();
        connection.wipe().unwrap();
    }
}

fn echo(conn: &mut s2n::Connection) -> Result<(), Box<::std::error::Error>> {
    use std::io::{Read, Write};
    writeln!(conn, "Hello from S2N!")?;

    let mut contents = String::new();
    conn.read_to_string(&mut contents)?;

    println!("Received '{}'", contents);

    Ok(())
}
