use std::{io, net::UdpSocket};
use aes::cipher::block_padding::ZeroPadding;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use common::pakets::*;
use common::utils::*;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

const URL: &str = "127.0.0.1:34254";

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    let session_opt = login(&socket);
    if session_opt.is_none() {
        return;
    }
    let session = session_opt.unwrap();
    loop {
        println!("{}", "Kommandos: 2: abfragen");
        let cmd = read_line();
        let cmd = cmd.parse().unwrap();
        let mut pb = PaketBuilder::new();
        pb.add_int(BANKING_COMMAND);
        pb.add_bytes(&session.session_id);
        match cmd {
            2 => show_balance(&session, &socket, pb),
            _ => {}
        }
    }
}

fn login(socket: &UdpSocket) -> Option<ClientSession> {
    //send email address to server
    println!("E-Mail-Adresse:");
    let email = read_line();
    println!("Passwort:");
    let password = read_line();
    let mut pb = PaketBuilder::new();
    pb.add_int(START_LOGIN);
    pb.add_string(email);
    let buf = pb.get_paket();
	let _ = socket.send_to(buf, URL).expect("couldn't send data");

    //receive 
    let mut buf = [0; 40];
    let (_amt, _src) = socket.recv_from(&mut buf).unwrap();
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
    let aes_enc = Aes256CbcEnc::new((&session_key_owned).into(), (&IV).into());
    let aes_dec = Aes256CbcDec::new((&session_key_owned).into(), (&IV).into());
    let ct = aes_enc.clone().encrypt_padded_mut::<NoPadding>(&mut password_hash, 32).unwrap();
    let mut pb = PaketBuilder::new();
    pb.add_int(COMPLETE_LOGIN);
    pb.add_bytes(&session_id_u8);
    pb.add_bytes(ct);
    let _ = socket.send_to(pb.get_paket(), URL);

    //receive ack
    let mut buf = [0; 4];
    let (_amt, _src) = socket.recv_from(&mut buf).unwrap();
    if int_to_u8(LOGIN_ACK).eq(&buf) {
        println!("login succeeded");
        Some(ClientSession { aes_enc : aes_enc, aes_dec : aes_dec, session_id: session_id_u8 })
    } else {
        println!("login not succeeded");
        None::<ClientSession>
    }
}

fn show_balance(session: &ClientSession, socket: &UdpSocket, mut pb: PaketBuilder) {
    let mut pb_enc = PaketBuilder::new();
    pb_enc.add_int(SHOW_BALANCE_COMMAND);
    let mut in_block: [u8; 16] = [0; 16];
    let paket = pb_enc.get_paket();
    in_block[..paket.len()].copy_from_slice(paket);
    let out_block = session.aes_enc.clone().encrypt_padded_mut::<ZeroPadding>(&mut in_block, 16).unwrap();
    pb.add_bytes(out_block);
    let _ = socket.send_to(pb.get_paket(), URL);

    //receive response
    let mut in_buf = [0; 16];
    let (_amt, _src) = socket.recv_from(&mut in_buf).unwrap();
    let mut out_buf = [0; 16];
    let _ct = session.aes_dec.clone().decrypt_padded_b2b_mut::<ZeroPadding>(&in_buf, &mut out_buf);
    let mut pr = PaketReader::new(&out_buf);
    if pr.get_int() == SHOW_BALANCE_RESPONSE {
        println!("{}", (pr.get_int() as f32) / 100.0);
    }
}

fn read_line() -> String {
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    s.replace("\n", "")
}

struct ClientSession {
    aes_enc: Aes256CbcEnc,
    aes_dec: Aes256CbcDec,
    session_id: [u8; 8],
}