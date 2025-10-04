use std::{io, net::UdpSocket};
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use common::pakets::*;
use common::utils::*;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

fn main() {
    //send email address to server
	let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    println!("E-Mail-Adresse:");
    let email = read_line();
    println!("Passwort:");
    let password = read_line();
    let mut pb = PaketBuilder::new();
    pb.add_int(START_LOGIN);
    pb.add_string(email);
    let buf = pb.get_paket();
	let _ = socket.send_to(buf, "127.0.0.1:34254").expect("couldn't send data");

    //receive 
    let mut buf = [0; 40];
    let (_amt, src) = socket.recv_from(&mut buf).unwrap();
    let mut pr = PaketReader::new(&buf);
    let session_id = pr.get_bytes(8);
    let mut session_id_u8: [u8; 8] = [0; 8];
    session_id_u8[..8].copy_from_slice(&session_id);


    let received_session_key = pr.get_bytes(32);
    let mut password_hash = create_hashcode_sha256(&password);
    let mut crypto_key: [u8; 32] = [0; 32];
    let ct = Aes256CbcDec::new((&password_hash).into(), (&IV).into()).decrypt_padded_b2b_mut::<NoPadding>(&received_session_key, &mut crypto_key).unwrap();
    //send password to server
    let mut session_key_owned: [u8; 32] = [0; 32];
    session_key_owned[..32].copy_from_slice(ct);
    let ct = Aes256CbcEnc::new((&session_key_owned).into(), (&IV).into()).encrypt_padded_mut::<NoPadding>(&mut password_hash, 32).unwrap();
    let mut pb = PaketBuilder::new();
    pb.add_int(COMPLETE_LOGIN);
    pb.add_bytes(&session_id_u8);
    pb.add_bytes(ct);
    let _ = socket.send_to(pb.get_paket(), src);

    //receive ack
    let mut buf = [0; 4];
    let (_amt, _src) = socket.recv_from(&mut buf).unwrap();
    if int_to_u8(LOGIN_ACK).eq(&buf) {
        println!("login succeeded")
    }
}

fn read_line() -> String {
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    s.replace("\n", "")
}