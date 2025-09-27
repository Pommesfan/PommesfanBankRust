use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes::cipher::{block_padding::NoPadding, KeyInit};
use std::net::{UdpSocket, SocketAddr};
use std::io::{Result};
mod db_interface;
use db_interface::DbInterface;
use common::paketbuilder::*;
mod sessions;
use sessions::{Session, SessionList};
mod utils;
use utils::*;
use sha2::{Sha256, Digest};

type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;

const START_LOGIN: i32 = 1;
const COMPLETE_LOGIN: i32 = 2;

fn main() -> Result<()> {
    {
        let db = DbInterface::new(String::from("Pommesfan_Bank_DB.db")).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:34254")?;
        let mut session_list = SessionList::new();

        loop {
            let mut buf = [0; 1024];
            let (_amt, src) = socket.recv_from(&mut buf)?;
            let mut pr = PaketReader::new(&buf);
            
            let cmd = pr.get_int();
            if cmd == START_LOGIN {
                start_login(pr, &db, &mut session_list, &socket, &src);
            } else if cmd == COMPLETE_LOGIN {
                complete_login(&mut pr, &mut session_list, &db);
            }
        }


    } // the socket is closed here
}

fn start_login(mut pr: PaketReader, db: &DbInterface, session_list: &mut SessionList, socket: &UdpSocket, src:&SocketAddr) {
    let email = pr.get_string();
    let email = email.replace("\n", "");
    let res = db.query_customer("email".to_string(), &email);

    let session_key = create_random_id(32);
    let mut session_key_b_owned: [u8; 32] = [0; 32];
    session_key_b_owned[..session_key.len()].copy_from_slice(&(session_key.as_bytes()));
    
    let session = Session::new(create_random_id(8), res.customer_id, session_key_b_owned);
    let session_id = session.session_id.clone();
    session_list.insert(session);

    let mut pb = PaketBuilder::new();
    pb.add_bytes(session_id.as_bytes());

    let key =  res.password.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(key);
    let mut key_owned: [u8; 32] = [0; 32];
    key_owned[..key.len()].copy_from_slice(&(key));
    
    let len = (&session_key_b_owned).len();
    let mut ct = Aes256EcbEnc::new((&key_owned).into()).encrypt_padded_mut::<NoPadding>(&mut session_key_b_owned, len).unwrap();
    pb.add_bytes(&mut ct);

    let _ = socket.send_to(pb.get_paket(), src);

}

fn complete_login(pr: &mut PaketReader, session_list: &mut SessionList, db: &DbInterface) {
    let received_session_id = pr.get_string_with_len(8);
    let session = session_list.get_session(&received_session_id);

    let received_password_hash = pr.get_bytes(32);
    let mut received_password_hash_owned: [u8; 32] = [0; 32];
    received_password_hash_owned[..32].copy_from_slice(&received_password_hash);
    
    //query customer password
    let password = db.query_customer(String::from("customer_id"), &session.customer_id).password;
    let password_b = password.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(password_b);
    let mut queried_password_hash: [u8; 32] = [0; 32];
    queried_password_hash[..password_b.len()].copy_from_slice(&password_b);

    let mut decrypted_password_hash: [u8; 32] = [0; 32];
    let _ct = Aes256EcbDec::new((&session.session_crypto).into()).decrypt_padded_b2b_mut::<NoPadding>(&received_password_hash, &mut decrypted_password_hash).unwrap();
    if queried_password_hash.iter().eq(&decrypted_password_hash) {
        session_list.remove_session(&received_session_id);
        println!("{}", "handshake successfull");
    }
}