use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes::cipher::{block_padding::NoPadding, KeyInit};
use std::net::{UdpSocket, SocketAddr};
use std::io::{Result};
use std::thread;
use std::sync::{Arc, Mutex};
mod db_interface;
use db_interface::DbInterface;
mod sessions;
use sessions::{Session, SessionList};
use common::pakets::*;
use common::utils::*;
use db_interface::QueryResCustomer;

type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;

const START_LOGIN: i32 = 1;
const COMPLETE_LOGIN: i32 = 2;

fn main() -> Result<()> {
    {
        let db = DbInterface::new(String::from("Pommesfan_Bank_DB.db")).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:34254")?;
        let session_list = SessionList::new();

        let db_arc = Arc::new(Mutex::new(db));
        let socket_arc = Arc::new(Mutex::new(socket));
        let session_list_arc = Arc::new(Mutex::new(session_list));


        for _i in 0 .. 4 {
            let db_arc = Arc::clone(&db_arc);
            let socket_arc = Arc::clone(&socket_arc);
            let session_list_arc = Arc::clone(&session_list_arc);

            let _ = thread::spawn(move || {
                routine(db_arc, socket_arc, session_list_arc);
            }).join();
        }
        Ok(())
    } // the socket is closed here
}

fn routine(db_mutex: Arc<Mutex<DbInterface>>, socket_mutex: Arc<Mutex<UdpSocket>>, session_list_mutex: Arc<Mutex<SessionList>>) {
    loop {
        let mut buf = [0; 1024];
        let (_amt, src): (usize, SocketAddr);
        {
            let socket = socket_mutex.lock().unwrap();
            (_amt, src) = socket.recv_from(&mut buf).unwrap();
        }
        
        let mut pr = PaketReader::new(&buf);
            
        let cmd = pr.get_int();
        if cmd == START_LOGIN {
            start_login(pr, &db_mutex, &session_list_mutex, &socket_mutex, &src);
        } else if cmd == COMPLETE_LOGIN {
            complete_login(&mut pr, &session_list_mutex, &db_mutex);
        }
    }
}

fn start_login(mut pr: PaketReader, db: &Arc<Mutex<DbInterface>>, session_list: &Arc<Mutex<SessionList>>, socket: &Arc<Mutex<UdpSocket>>, src:&SocketAddr) {
    let email = pr.get_string();
    let email = email.replace("\n", "");
    let res: QueryResCustomer;
    {
        let db = db.lock().unwrap();
        res = db.query_customer("email".to_string(), &email);
    }
    
    let session_key = create_random_id(32);
    let mut session_key_b_owned: [u8; 32] = [0; 32];
    session_key_b_owned[..session_key.len()].copy_from_slice(&(session_key.as_bytes()));
    
    let session = Session::new(create_random_id(8), res.customer_id, session_key_b_owned);
    let session_id = session.session_id.clone();
    {
        session_list.lock().unwrap().insert(session);
    }

    let mut pb = PaketBuilder::new();
    pb.add_bytes(session_id.as_bytes());

    let password_hash = create_hashcode_sha256(&res.password);
    
    let len = (&session_key_b_owned).len();
    let mut ct = Aes256EcbEnc::new((&password_hash).into()).encrypt_padded_mut::<NoPadding>(&mut session_key_b_owned, len).unwrap();
    pb.add_bytes(&mut ct);

    {
        let socket = socket.lock().unwrap();
        let _ = socket.send_to(pb.get_paket(), src);
    }
}

fn complete_login(pr: &mut PaketReader, session_list: &Arc<Mutex<SessionList>>, db: &Arc<Mutex<DbInterface>>) {
    let received_session_id = pr.get_string_with_len(8);

    let mut session_list = session_list.lock().unwrap();
    let session = session_list.get_session(&received_session_id);

    let received_password_hash = pr.get_bytes(32);
    let mut received_password_hash_owned: [u8; 32] = [0; 32];
    received_password_hash_owned[..32].copy_from_slice(&received_password_hash);
    
    //query customer password
    let queried_password: String;
    {
        let db = db.lock().unwrap();
        queried_password = db.query_customer(String::from("customer_id"), &session.customer_id).password;
    }

    let queried_password_hash = create_hashcode_sha256(&queried_password);

    let mut decrypted_password_hash: [u8; 32] = [0; 32];
    let _ct = Aes256EcbDec::new((&session.session_crypto).into()).decrypt_padded_b2b_mut::<NoPadding>(&received_password_hash, &mut decrypted_password_hash).unwrap();
    let session = session_list.remove_session(&received_session_id);
    if queried_password_hash.iter().eq(&decrypted_password_hash) {
        println!("{}", "handshake successfull");
    }
}