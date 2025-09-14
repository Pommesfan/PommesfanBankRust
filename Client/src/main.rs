use std::{cmp, f32::consts::E, io, net::UdpSocket};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use hex_literal::hex;
use sha256::digest;
mod paketbuilder;
use paketbuilder::PaketBuilder;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;

const START_LOGIN: i32 = 1;
const COMPLETE_LOGIN: i32 = 2;

fn main() {
	let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    println!("E-Mail-Adresse:");
    let mut email = String::new();
    io::stdin().read_line(&mut email);
    println!("Passwort:");
    let mut password = String::new();
    io::stdin().read_line(&mut password);
    let mut pb = PaketBuilder::new();
    pb.add_int(START_LOGIN);
    pb.add_string(email);
    let mut buf = pb.get_paket();

    //let key =  digest(password).as_bytes();
    //let ct = Aes128EcbEnc::new(key.into()).encrypt_padded_mut::<Pkcs7>(&mut buf, buf.len()).unwrap();

	socket.send_to(buf, "127.0.0.1:34254").expect("couldn't send data");
}