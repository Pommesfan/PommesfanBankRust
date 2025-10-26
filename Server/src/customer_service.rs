use aes::cipher::block_padding::ZeroPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes::cipher::{block_padding::NoPadding, KeyIvInit};
use std::net::{UdpSocket, SocketAddr};
use std::sync::{Arc, Mutex};
use common::utils::*;
use common::pakets::*;
use crate::db_interface::DbInterface;
use crate::sessions::Session;
use crate::sessions::SessionList;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub struct CustomerService {
    db_arc: Arc<Mutex<DbInterface>>,
    socket_arc: Arc<Mutex<UdpSocket>>,
    ongoing_session_list_arc: Arc<Mutex<SessionList>>,
    session_list_arc: Arc<Mutex<SessionList>>,
}

impl CustomerService {
    pub fn new(db_arc: Arc<Mutex<DbInterface>>, socket_arc: Arc<Mutex<UdpSocket>>, ongoing_session_list_arc: Arc<Mutex<SessionList>>, session_list_arc: Arc<Mutex<SessionList>>) -> CustomerService {
        CustomerService {
            db_arc: db_arc,
            socket_arc: socket_arc,
            ongoing_session_list_arc: ongoing_session_list_arc,
            session_list_arc: session_list_arc
        }
    }
    pub fn routine(&self) {
        loop {
            let mut buf = [0; 1024];
            let (amt, src): (usize, SocketAddr);
            {
                let socket = (&self.socket_arc).lock().unwrap();
                (amt, src) = socket.recv_from(&mut buf).unwrap();
            }
        
            let mut pr = PaketReader::new(&buf);
            let cmd = pr.get_int();
            if cmd == START_LOGIN {
                self.start_login(pr, &src);
            } else if cmd == COMPLETE_LOGIN {
                self.complete_login(&mut pr, &src);
            } else if cmd == BANKING_COMMAND {
                let session_id = pr.get_string_with_len(8);
                let encrypted_packet = pr.get_bytes(amt - 12);
                let customer_id;
                let session_crypto: [u8; 32];
                {
                    let session_list = &self.session_list_arc.lock().unwrap();
                    let session = session_list.get_session(&session_id);
                    session_crypto = session.session_crypto.clone();
                    customer_id = session.customer_id.clone();
                }
                const ENCRYPTION_SIZE: usize = 128;
                let mut in_buf: [u8; ENCRYPTION_SIZE] = [0; ENCRYPTION_SIZE];
                in_buf[..encrypted_packet.len()].copy_from_slice(&encrypted_packet);
                let mut out_buf: [u8; ENCRYPTION_SIZE] = [0; ENCRYPTION_SIZE];
                let _ct = Aes256CbcDec::new((&session_crypto).into(), (&IV).into()).decrypt_padded_b2b_mut::<ZeroPadding>(&in_buf, &mut out_buf).unwrap();
                pr = PaketReader::new(&out_buf);
                let cmd = pr.get_int();
                if cmd == SHOW_BALANCE_COMMAND {
                    self.show_balance(customer_id, session_crypto, src);
                }
            }
        }
    }

    fn start_login(&self, mut pr: PaketReader, src:&SocketAddr) {
        let email = pr.get_string();
        let email = email.replace("\n", "");
        let res: (String, String);
        {
            let db = &self.db_arc.lock().unwrap();
            res = db.query_customer_from_email(&email);
        }
    
        let session_key = create_random_id(32);
        let mut session_key_b_owned: [u8; 32] = [0; 32];
        session_key_b_owned[..session_key.len()].copy_from_slice(&(session_key.as_bytes()));
    
        let session = Session::new(create_random_id(8), res.0, session_key_b_owned);
        let session_id = session.session_id.clone();
        {
            let _ = &self.ongoing_session_list_arc.lock().unwrap().insert(session);
        }

        let mut pb = PaketBuilder::new();
        pb.add_bytes(session_id.as_bytes());

        let password_hash = create_hashcode_sha256(&res.1);
    
        let len = (&session_key_b_owned).len();
        let mut ct = Aes256CbcEnc::new((&password_hash).into(), (&IV).into()).encrypt_padded_mut::<NoPadding>(&mut session_key_b_owned, len).unwrap();
        pb.add_bytes(&mut ct);

        {
            let socket = &self.socket_arc.lock().unwrap();
            let _ = socket.send_to(pb.get_paket(), src);
        }
    }

    fn complete_login(&self, pr: &mut PaketReader, src:&SocketAddr) {
        let received_session_id = pr.get_string_with_len(8);

        let mut ongoing_session_list = &mut self.ongoing_session_list_arc.lock().unwrap();
        let session = ongoing_session_list.get_session(&received_session_id);

        let received_password_hash = pr.get_bytes(32);
        let mut received_password_hash_owned: [u8; 32] = [0; 32];
        received_password_hash_owned[..32].copy_from_slice(&received_password_hash);
    
        //query customer password
        let queried_password: String;
        {
            let db = &self.db_arc.lock().unwrap();
            queried_password = db.query_customer_from_id(&session.customer_id).1;
        }

        let queried_password_hash = create_hashcode_sha256(&queried_password);

        let mut decrypted_password_hash: [u8; 32] = [0; 32];
        let _ct = Aes256CbcDec::new((&session.session_crypto).into(), (&IV).into()).decrypt_padded_b2b_mut::<NoPadding>(&received_password_hash, &mut decrypted_password_hash).unwrap();
        let session = ongoing_session_list.remove_session(&received_session_id);
        if queried_password_hash.iter().eq(&decrypted_password_hash) {
            println!("{}", "handshake successfull");
            let socket = &self.socket_arc.lock().unwrap();
            let _ = socket.send_to(&int_to_u8(LOGIN_ACK), src);
            let mut session_list = &mut self.session_list_arc.lock().unwrap();
            session_list.insert(session);
        } else {
            let socket = &self.socket_arc.lock().unwrap();
            let _ = socket.send_to(&int_to_u8(LOGIN_NACK), src);
        }
    }

    fn show_balance(&self, customer_id: String, session_crypto: [u8; 32], src: SocketAddr) {
        let balance: i32;
        {
            let db = &self.db_arc.lock().unwrap();
            balance = db.query_balance(&db.query_account_to_customer(&customer_id));
        }
        let mut pb = PaketBuilder::new();
        pb.add_int(SHOW_BALANCE_RESPONSE);
        pb.add_int(balance);

        let mut in_buf: [u8; 16] = [0; 16];
        in_buf[..8].copy_from_slice(pb.get_paket());
        let mut out_buf: [u8; 16] = [0; 16];

        let _ct = Aes256CbcEnc::new((&session_crypto).into(), (&IV).into()).encrypt_padded_b2b_mut::<ZeroPadding>(&mut in_buf, &mut out_buf).unwrap();
        {
            let _ = &self.socket_arc.lock().unwrap().send_to(&out_buf, src);
        }
    }
}