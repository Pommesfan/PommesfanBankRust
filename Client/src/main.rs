use std::net::TcpStream;
use core::net::SocketAddr;
use std::net::UdpSocket;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut};
use common::aes_streams::AesInputStream;
use common::pakets::*;
use common::utils::*;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    let session_opt = login(&socket);
    if session_opt.is_none() {
        return;
    }
    let (session, _src) = session_opt.unwrap();
    loop {
        println!("{}", "Kommandos: 1:abmelden, 2: abfragen; 3: Überweisen; 4: Umsatzübersicht");
        let cmd = read_int();
        match cmd {
            1 => exit_session(&session, &socket),
            2 => show_balance(&session, &socket),
            3 => transfer(&session, &socket),
            4 => show_turnover(&session, &socket),
            _ => {}
        }
    }
}

fn write_header(session: &ClientSession, pb: &mut PaketBuilder) {
    pb.add_int(BANKING_COMMAND);
    pb.add_bytes(&session.session_id);
}

fn send_to_server(socket: &UdpSocket, session: &ClientSession, mut pb: PaketBuilder) {
    pb.encrypt(&session.session_crypto, 12);
    let _ = socket.send_to(&pb.get_paket(), create_udp_read_url());
}

fn login(socket: &UdpSocket) -> Option<(ClientSession, SocketAddr)> {
    let read_url = create_udp_read_url();
    //send email address to server
    println!("E-Mail-Adresse:");
    let email = read_line();
    println!("Passwort:");
    let password = read_line();
    let mut pb = PaketBuilder::new(16);
    pb.add_int(START_LOGIN);
    pb.add_string(email);
	let _ = socket.send_to(&pb.get_paket(), &read_url).expect("couldn't send data");

    //receive 
    let mut buf = [0; 80];
    let (_amt, src) = socket.recv_from(&mut buf).unwrap();
    let mut pr = PaketReader::new(&mut buf);
    let session_id = pr.get_bytes_fixed::<8>();
    let mut crypto_key = pr.get_bytes_fixed::<32>();
    let mut password_hash = create_hashcode_sha256(&password);
    create_decryptor(&password_hash).decrypt_padded_mut::<NoPadding>(&mut crypto_key).unwrap();
    let currency = pr.get_string();
    let decimal_place = pr.get_int();
    
    //send password to server
    let aes_enc = create_encryptor(&crypto_key);
    let len = (&password_hash).len();
    let _ = aes_enc.encrypt_padded_mut::<NoPadding>(&mut password_hash, len).unwrap();
    let mut pb = PaketBuilder::new(48);
    pb.add_int(COMPLETE_LOGIN);
    pb.add_bytes(&session_id);
    pb.add_bytes(&password_hash);
    let _ = socket.send_to(&pb.get_paket(), &read_url);

    //receive ack
    let mut buf = [0; 4];
    let (_amt, _src) = socket.recv_from(&mut buf).unwrap();
    if int_to_u8(LOGIN_ACK).eq(&buf) {
        println!("login succeeded");
        Some((ClientSession { session_crypto: crypto_key, session_id: session_id, currency: currency, decimal_place: decimal_place }, src))
    } else {
        println!("login not succeeded");
        None::<(ClientSession, SocketAddr)>
    }
}

fn exit_session(session: &ClientSession, socket: &UdpSocket) {
    let mut pb = PaketBuilder::new(16);
    write_header(session, &mut pb);
    pb.add_int(EXIT_COMMAND);
    send_to_server(socket, session, pb);
    std::process::exit(0);
}

fn print_turnover(mut pr: PaketReader, session: &ClientSession) {
    let tcp_url = create_url(pr.get_int());
    let tcp_socket = TcpStream::connect(tcp_url).unwrap();
    let mut input = AesInputStream::<AES_STREAMS_BUFFER_SIZE>::new(tcp_socket, &session.session_crypto);
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
        println!("{0}|{1}|{2}|{3}|{4}", customer_name, account_id, format_amount(amount, session), date, reference);
    }
}

fn receive_response(session: &ClientSession, socket: &UdpSocket) {
    //receive response
    let mut in_buf = [0; 16];
    let (_amt, _src) = socket.recv_from(&mut in_buf).unwrap();
    let mut pr = PaketReader::from_encrypted(&mut in_buf, &session.session_crypto);
    let response = pr.get_int();
    match response {
        SHOW_BALANCE_RESPONSE => println!("{}", format_amount(pr.get_int(), session)),
        SEE_TURNOVER_RESPONSE => print_turnover(pr, session),
        _ => {}
    }
}

fn show_balance(session: &ClientSession, socket: &UdpSocket) {
    let mut pb = PaketBuilder::new(16);
    write_header(session, &mut pb);
    pb.add_int(SHOW_BALANCE_COMMAND);
    send_to_server(socket, session, pb);
    receive_response(session, socket);
}

fn transfer(session: &ClientSession, socket: &UdpSocket) {
    println!("E-Mail-Adresse Empfänger:");
    let email = read_line();
    println!("Betrag:");
    let amount = (read_float() * 100.0) as i32;
    println!("Verwendungszweck:");
    let reference = read_line();
    let mut pb = PaketBuilder::new(16 + email.len() + reference.len());
    write_header(session, &mut pb);
    pb.add_int(TRANSFER_COMMAND);
    pb.add_string(email);
    pb.add_int(amount);
    pb.add_string(reference);
    send_to_server(socket, session, pb);
}

fn show_turnover(session: &ClientSession, socket: &UdpSocket) {
    let mut pb = PaketBuilder::new(16);
    write_header(session, &mut pb);
    pb.add_int(SEE_TURNOVER);
    send_to_server(socket, session, pb);
    receive_response(session, socket);
}

fn format_amount(amount: i32, session: &ClientSession) -> String {
    let n = (amount as f64) / (10_u32.pow(session.decimal_place as u32)) as f64;
    let mut s = format!("{:.2}", n);
    s.push(' ');
    s.push_str(&session.currency);
    s
}

struct ClientSession {
    session_crypto: [u8; 32],
    session_id: [u8; 8],
    currency: String,
    decimal_place: i32
}