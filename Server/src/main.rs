use aes::cipher::block_padding::ZeroPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes::cipher::{block_padding::NoPadding, KeyIvInit};
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

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

fn main() -> Result<()> {
    {
        let db = DbInterface::new(String::from("Pommesfan_Bank_DB.db")).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:34254")?;
        let ongoing_session_list = SessionList::new();
        let session_list = SessionList::new();

        let db_arc = Arc::new(Mutex::new(db));
        let socket_arc = Arc::new(Mutex::new(socket));
        let ongoing_session_list_arc = Arc::new(Mutex::new(ongoing_session_list));
        let session_list_arc = Arc::new(Mutex::new(session_list));


        for _i in 0 .. 4 {
            let db_arc = Arc::clone(&db_arc);
            let socket_arc = Arc::clone(&socket_arc);
            let ongoing_session_list_arc = Arc::clone(&ongoing_session_list_arc);
            let session_list_arc = Arc::clone(&session_list_arc);

            let _ = thread::spawn(move || {
                routine(db_arc, socket_arc, ongoing_session_list_arc, session_list_arc);
            }).join();
        }
        Ok(())
    } // the socket is closed here
}

fn routine(db_mutex: Arc<Mutex<DbInterface>>, socket_mutex: Arc<Mutex<UdpSocket>>, ongoing_session_list_mutex: Arc<Mutex<SessionList>>, session_list_mutex: Arc<Mutex<SessionList>>) {
    loop {
        let mut buf = [0; 1024];
        let (amt, src): (usize, SocketAddr);
        {
            let socket = (&socket_mutex).lock().unwrap();
            (amt, src) = socket.recv_from(&mut buf).unwrap();
        }
        
        let mut pr = PaketReader::new(&buf);
            
        let cmd = pr.get_int();
        if cmd == START_LOGIN {
            start_login(pr, &db_mutex, &ongoing_session_list_mutex, &socket_mutex, &src);
        } else if cmd == COMPLETE_LOGIN {
            complete_login(&mut pr, &ongoing_session_list_mutex, &session_list_mutex, &db_mutex, &socket_mutex, &src);
        } else if cmd == BANKING_COMMAND {
            let session_id = pr.get_string_with_len(8);
            let encrypted_packet = pr.get_bytes(amt - 12);
            let customer_id;
            let session_crypto: [u8; 32];
            {
                let session_list = session_list_mutex.lock().unwrap();
                let session = session_list.get_session(&session_id);
                session_crypto = session.session_crypto.clone();
                customer_id = session.customer_id.clone();
            }
            const encryption_size: usize = 128;
            let mut in_buf: [u8; encryption_size] = [0; encryption_size];
            in_buf[..encrypted_packet.len()].copy_from_slice(&encrypted_packet);
            let mut out_buf: [u8; encryption_size] = [0; encryption_size];
            let ct = Aes256CbcDec::new((&session_crypto).into(), (&IV).into()).decrypt_padded_b2b_mut::<ZeroPadding>(&in_buf, &mut out_buf).unwrap();
            pr = PaketReader::new(&out_buf);
            let cmd = pr.get_int();
            if cmd == SHOW_BALANCE_COMMAND {
                show_balance(customer_id, session_crypto, &socket_mutex, src, &db_mutex);
            }
        }
    }
}

fn start_login(mut pr: PaketReader, db: &Arc<Mutex<DbInterface>>, ongoing_session_list: &Arc<Mutex<SessionList>>, socket: &Arc<Mutex<UdpSocket>>, src:&SocketAddr) {
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
        ongoing_session_list.lock().unwrap().insert(session);
    }

    let mut pb = PaketBuilder::new();
    pb.add_bytes(session_id.as_bytes());

    let password_hash = create_hashcode_sha256(&res.password);
    
    let len = (&session_key_b_owned).len();
    let mut ct = Aes256CbcEnc::new((&password_hash).into(), (&IV).into()).encrypt_padded_mut::<NoPadding>(&mut session_key_b_owned, len).unwrap();
    pb.add_bytes(&mut ct);

    {
        let socket = socket.lock().unwrap();
        let _ = socket.send_to(pb.get_paket(), src);
    }
}

fn complete_login(pr: &mut PaketReader, ongoing_session_list: &Arc<Mutex<SessionList>>, session_list: &Arc<Mutex<SessionList>>, db: &Arc<Mutex<DbInterface>>, socket: &Arc<Mutex<UdpSocket>>, src:&SocketAddr) {
    let received_session_id = pr.get_string_with_len(8);

    let mut ongoing_session_list = ongoing_session_list.lock().unwrap();
    let session = ongoing_session_list.get_session(&received_session_id);

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
    let _ct = Aes256CbcDec::new((&session.session_crypto).into(), (&IV).into()).decrypt_padded_b2b_mut::<NoPadding>(&received_password_hash, &mut decrypted_password_hash).unwrap();
    let session = ongoing_session_list.remove_session(&received_session_id);
    if queried_password_hash.iter().eq(&decrypted_password_hash) {
        println!("{}", "handshake successfull");
        let socket = socket.lock().unwrap();
        let _ = socket.send_to(&int_to_u8(LOGIN_ACK), src);
        let mut session_list = session_list.lock().unwrap();
        session_list.insert(session);
    } else {
        let socket = socket.lock().unwrap();
        let _ = socket.send_to(&int_to_u8(LOGIN_NACK), src);
    }
}

fn show_balance(customer_id: String, session_crypto: [u8; 32], socket_mutex: &Arc<Mutex<UdpSocket>>, src: SocketAddr, db_mutex: &Arc<Mutex<DbInterface>>) {
    let balance: i32;
    {
        let db = db_mutex.lock().unwrap();
        balance = db.query_balance(&db.query_account_to_customer(&customer_id));
    }
    let mut pb = PaketBuilder::new();
    pb.add_int(SHOW_BALANCE_RESPONSE);
    pb.add_int(balance);

    let mut in_buf: [u8; 16] = [0; 16];
    in_buf[..8].copy_from_slice(pb.get_paket());
    let mut out_buf: [u8; 16] = [0; 16];

    let mut ct = Aes256CbcEnc::new((&session_crypto).into(), (&IV).into()).encrypt_padded_b2b_mut::<ZeroPadding>(&mut in_buf, &mut out_buf).unwrap();
    {
        let _ = socket_mutex.lock().unwrap().send_to(&out_buf, src);
    }
}
