extern crate enum_primitive;
extern crate tls_parser;

use enum_primitive::FromPrimitive;
use std::env;
use std::fs::File;
use std::io::Read;
use std::str;
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
    match parse_tls_plaintext(&contents) {
        Ok((_, record)) => dump_record(&record),
        Err(e) => panic!("error parsing TLS record: {}", e),
    }
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
        println!("  {:?}", ciphersuite);
    }
    println!("compression methods:");
    for compression_method in &client_hello.comp {
        println!("  {:?}", compression_method);
    }
    if let Some(extension_bytes) = client_hello.ext {
        println!("extensions:");
        match parse_tls_extensions(extension_bytes) {
            Ok((_, extensions)) => for extension in extensions {
                dump_extension(&extension);
            }
            Err(e) => println!("  couldn't parse extension: {}", e),
        }
    } else {
        println!("no extensions");
    }
}

fn dump_extension(extension: &TlsExtension) {
    if let &TlsExtension::SignatureAlgorithms(ref signature_algorithms) = extension {
        println!("  TlsExtension::SignatureAlgorithms([");
        for signature_algorithm in signature_algorithms {
            if let Some(hash_algorithm) = HashAlgorithm::from_u8(signature_algorithm.0) {
                print!("    {:?}", hash_algorithm);
            } else {
                print!("    <Unknown hash 0x{:x}>", signature_algorithm.0);
            }
            if let Some(signature_algorithm) = SignAlgorithm::from_u8(signature_algorithm.1) {
                println!("/{:?},", signature_algorithm);
            } else {
                println!("/<Unknown signature 0x{:x}>,", signature_algorithm.1);
            }
        }
        println!("  ])");
    } else if let &TlsExtension::EllipticCurves(ref curves) = extension {
        println!("  TlsExtension::EllipticCurves([");
        for curve in curves {
            if let Some(named_group) = NamedGroup::from_u16(*curve) {
                println!("    {:?},", named_group);
            } else {
                println!("    <Unknown curve 0x{:x}>,", curve);
            }
        }
        println!("  ])");
    } else if let &TlsExtension::ALPN(ref alpns) = extension {
        println!("  TlsExtension::ALPN([");
        for alpn in alpns {
            if let Ok(as_string) = str::from_utf8(alpn) {
                println!("    {},", as_string);
            } else {
                println!("    {:?}", alpn);
            }
        }
        println!("  ])");
    } else {
        println!("  {:#?}", extension);
    }
}
