use std::{f32::consts::E, io, net::UdpSocket};
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyInit};
use sha2::{Sha256, Digest};
mod paketbuilder;
use paketbuilder::*;

type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;

const START_LOGIN: i32 = 1;
const COMPLETE_LOGIN: i32 = 2;

fn main() {
    //send email address to server
	let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    println!("E-Mail-Adresse:");
    let mut email = String::new();
    io::stdin().read_line(&mut email);
    println!("Passwort:");
    let mut password = String::new();
    io::stdin().read_line(&mut password);
    password = password.replace("\n", "");
    let mut pb = PaketBuilder::new();
    pb.add_int(START_LOGIN);
    pb.add_string(email);
    let mut buf = pb.get_paket();
	socket.send_to(buf, "127.0.0.1:34254").expect("couldn't send data");

    //receive 
    let mut buf = [0; 40];
    let (amt, src) = socket.recv_from(&mut buf).unwrap();
    let mut pr = PaketReader::new(&buf);

    let session_id = pr.get_bytes(8);
    let mut session_id_u8: [u8; 8] = [0; 8];
    session_id_u8[..8].copy_from_slice(&session_id);

    let mut password_b =  password.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(password_b);
    let mut key_owned: [u8; 32] = [0; 32];
    key_owned[..password_b.len()].copy_from_slice(&(password_b));

    let received_session_key = pr.get_bytes(32);

    let mut crypto_key: [u8; 32] = [0; 32];
    let ct = Aes256EcbDec::new((&key_owned).into()).decrypt_padded_b2b_mut::<NoPadding>(&received_session_key, &mut crypto_key).unwrap();
    //send password to server
    let mut session_key_owned: [u8; 32] = [0; 32];
    session_key_owned[..32].copy_from_slice(ct);
    let ct = Aes256EcbEnc::new((&session_key_owned).into()).encrypt_padded_mut::<NoPadding>(&mut key_owned, 32).unwrap();
    let mut pb = PaketBuilder::new();
    pb.add_int(COMPLETE_LOGIN);
    pb.add_bytes(&session_id_u8);
    pb.add_bytes(ct);
    socket.send_to(pb.get_paket(), src);
}