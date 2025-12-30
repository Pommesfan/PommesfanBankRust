use std::net::TcpStream;
use core::net::SocketAddr;
use std::{io, net::UdpSocket};
use aes::cipher::block_padding::ZeroPadding;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use common::aes_streams::AesInputStream;
use common::pakets::*;
use common::utils::*;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    let session_opt = login(&socket);
    if session_opt.is_none() {
        return;
    }
    let (session, src) = session_opt.unwrap();
    loop {
        println!("{}", "Kommandos: 1:abmelden, 2: abfragen; 3: Überweisen; 4: Umsatzübersicht");
        let cmd = read_int();
        match cmd {
            1 => exit_session(&session, &socket, &src),
            2 => show_balance(&session, &socket, &src),
            3 => transfer(&session, &socket, &src),
            4 => show_turnover(&session, &socket, &src),
            _ => {}
        }
    }
}

fn send_to_server<const COUNT: usize>(socket: &UdpSocket, src: &SocketAddr, session: &ClientSession, paket: &[u8]) {
    let mut pb = PaketBuilder::new();
    pb.add_int(BANKING_COMMAND);
    pb.add_bytes(&session.session_id);

    let mut in_block: [u8; COUNT] = [0; COUNT];
    in_block[..paket.len()].copy_from_slice(paket);
    let out_block = session.aes_enc.clone().encrypt_padded_mut::<ZeroPadding>(&mut in_block, COUNT).unwrap();
    pb.add_bytes(out_block);
    let _ = socket.send_to(pb.get_paket(), src);
}

fn login(socket: &UdpSocket) -> Option<(ClientSession, SocketAddr)> {
    //send email address to server
    println!("E-Mail-Adresse:");
    let email = read_line();
    println!("Passwort:");
    let password = read_line();
    let mut pb = PaketBuilder::new();
    pb.add_int(START_LOGIN);
    pb.add_string(email);
    let buf = pb.get_paket();
	let _ = socket.send_to(buf, create_udp_url()).expect("couldn't send data");

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
    let aes_enc = Aes256CbcEnc::new((&session_key_owned).into(), (&IV).into());
    let aes_dec = Aes256CbcDec::new((&session_key_owned).into(), (&IV).into());
    let ct = aes_enc.clone().encrypt_padded_mut::<NoPadding>(&mut password_hash, 32).unwrap();
    let mut pb = PaketBuilder::new();
    pb.add_int(COMPLETE_LOGIN);
    pb.add_bytes(&session_id_u8);
    pb.add_bytes(ct);
    let _ = socket.send_to(pb.get_paket(), src);

    //receive ack
    let mut buf = [0; 4];
    let (_amt, _src) = socket.recv_from(&mut buf).unwrap();
    if int_to_u8(LOGIN_ACK).eq(&buf) {
        println!("login succeeded");
        Some((ClientSession { aes_enc : aes_enc, aes_dec : aes_dec, session_id: session_id_u8 }, src))
    } else {
        println!("login not succeeded");
        None::<(ClientSession, SocketAddr)>
    }
}

fn exit_session(session: &ClientSession, socket: &UdpSocket, src: &SocketAddr) {
    let mut pb_enc = PaketBuilder::new();
    pb_enc.add_int(EXIT_COMMAND);
    send_to_server::<16>(socket, src, session, pb_enc.get_paket());
    std::process::exit(0);
}

fn show_balance(session: &ClientSession, socket: &UdpSocket, src: &SocketAddr) {
    let mut pb_enc = PaketBuilder::new();
    pb_enc.add_int(SHOW_BALANCE_COMMAND);
    send_to_server::<16>(socket, src, session, pb_enc.get_paket());

    //receive response
    let mut in_buf = [0; 16];
    let (_amt, _src) = socket.recv_from(&mut in_buf).unwrap();
    let mut out_buf = [0; 16];
    let _ct = session.aes_dec.clone().decrypt_padded_b2b_mut::<ZeroPadding>(&in_buf, &mut out_buf);
    let mut pr = PaketReader::new(&out_buf);
    if pr.get_int() == SHOW_BALANCE_RESPONSE {
        println!("{}", (pr.get_int() as f64) / 100.0);
    }
}

fn transfer(session: &ClientSession, socket: &UdpSocket, src: &SocketAddr) {
    println!("E-Mail-Adresse Empfänger:");
    let email = read_line();
    println!("Betrag:");
    let amount = (read_float() * 100.0) as i32;
    println!("Verwendungszweck:");
    let reference = read_line();
    let mut pb = PaketBuilder::new();
    pb.add_int(TRANSFER_COMMAND);
    pb.add_string(email);
    pb.add_int(amount);
    pb.add_string(reference);
    send_to_server::<128>(socket, src, session, pb.get_paket());
}

fn show_turnover(session: &ClientSession, socket: &UdpSocket, src: &SocketAddr) {
    let mut pb = PaketBuilder::new();
    pb.add_int(SEE_TURNOVER);
    send_to_server::<16>(socket, src, session, pb.get_paket());
    //receive response
    let mut in_buf = [0; 16];
    let (_amt, _src) = socket.recv_from(&mut in_buf).unwrap();
    let mut out_buf = [0; 16];
    let _ct = session.aes_dec.clone().decrypt_padded_b2b_mut::<ZeroPadding>(&in_buf, &mut out_buf);
    let mut pr = PaketReader::new(&out_buf);
    if pr.get_int() != SEE_TURNOVER_RESPONSE{
        return;
    }
    let tcp_port =  pr.get_int();
    let mut tcp_url = String::from("127.0.0.1:");
    tcp_url.push_str(&tcp_port.to_string());
    let tcp_socket = TcpStream::connect(tcp_url).unwrap();
    let mut input = AesInputStream::<AES_STREAMS_BUFFER_SIZE>::new(tcp_socket, session.aes_dec.clone());
    loop {
        let transfer_type = input.read_int();
        if transfer_type == TERMINATION {
            return;
        }
        let customer_name = input.read_string();
        let account_id = input.read_string();
        let amount = input.read_int();
        let date = input.read_string();
        let reference = input.read_string();
        println!("{0}|{1}|{2}|{3}|{4}", customer_name, account_id, (amount as f64) / 100.0, date, reference);
    }
}

fn read_line() -> String {
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    s.replace("\n", "")
}

fn read_int() -> i32 {
    read_line().parse().unwrap()
}

fn read_float() -> f64 {
    read_line().parse().unwrap()
}

struct ClientSession {
    aes_enc: Aes256CbcEnc,
    aes_dec: Aes256CbcDec,
    session_id: [u8; 8],
}