use std::{cmp, net::UdpSocket, io};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use hex_literal::hex;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;

fn main() {
	let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    println!("Kommando eingeben:");
    let mut cmd = String::new();
    io::stdin().read_line(&mut cmd);

    let mut buf = [0u8; 48];
    let pt_len = cmd.len();
    buf[..pt_len].copy_from_slice(&(cmd.as_bytes()));

    let key = [0x42; 16];
    let ct = Aes128EcbEnc::new(&key.into()).encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
    .unwrap();

	socket.send_to(ct, "127.0.0.1:34254").expect("couldn't send data");
}