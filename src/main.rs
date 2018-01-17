extern crate nom;
extern crate tls_parser;

use nom::IResult;
use std::env;
use std::fs::File;
use std::io::Read;
use tls_parser::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        dump_handshake(&args[1]);
    } else {
        println!("usage: {} <input file>", args[0]);
    }
}

fn dump_handshake(filename: &str) {
    let mut file = File::open(filename).expect("file not found");
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).expect("couldn't read file");
    let result = parse_tls_plaintext(&contents);
    match result {
        IResult::Done(_, record) => {
            dump_record(&record);
        },
        IResult::Incomplete(_) => {
            panic!("incomplete?");
        },
        IResult::Error(e) => {
            panic!("couldn't read: {}", e);
        }
    };
}

fn dump_record(record: &TlsPlaintext) {
    println!("outer version: 0x{:04x}", record.hdr.version);
    if record.msg.len() < 1 {
       panic!("expected at least one message");
    }
    let msg = &record.msg[0];
    let handshake = match msg {
       &TlsMessage::Handshake(ref handshake) => handshake,
       _ => panic!("expected handshake message"),
    };
    let client_hello = match handshake {
       &TlsMessageHandshake::ClientHello(ref client_hello) => client_hello,
       _ => panic!("expected client hello"),
    };
    println!("inner version: 0x{:04x}", client_hello.version);
    // TODO: session id and whatnot
    println!("ciphersuites:");
    for ciphersuite in &client_hello.ciphers {
        let ciphersuite_name = match TlsCipherSuite::from_id(*ciphersuite) {
            Some(tls_cipher_suite) => tls_cipher_suite.name,
            None => "UNKNOWN",
        };
        println!("  {} (0x{:04x})", ciphersuite_name, ciphersuite);
    }
    println!("compression methods:");
    for compression_method in &client_hello.comp {
        println!("  {}", compression_method);
    }
    if let Some(extension_bytes) = client_hello.ext {
        println!("extensions:");
        let result = parse_tls_extensions(extension_bytes);
        match result {
            IResult::Done(_, extensions) => {
                for extension in extensions {
                    println!("  {:#?}", extension);
                }
            },
            IResult::Incomplete(_) => {
                println!("  incomplete extension?");
            },
            IResult::Error(e) => {
                println!("  couldn't read extension: {}", e);
            }
        };
    } else {
        println!("no extensions");
    }
}
