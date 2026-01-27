use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes::cipher::{block_padding::NoPadding, KeyIvInit};
use common::aes_streams::AesOutputStream;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use common::utils::*;
use common::pakets::*;
use crate::db_interface::DbInterface;
use crate::sessions::Session;
use crate::sessions::SessionList;
use chrono::prelude::*;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub struct CustomerService {
    db_arc: Arc<Mutex<DbInterface>>,
    socket_arc_read: Arc<Mutex<UdpSocket>>,
    socket_arc_write: Arc<Mutex<UdpSocket>>,
    ongoing_session_list_arc: Arc<Mutex<SessionList>>,
    session_list_arc: Arc<Mutex<SessionList>>,
    tcp_port: i32,
    tcp_socket: TcpListener
}

impl CustomerService {
    pub fn new(db_arc: Arc<Mutex<DbInterface>>, socket_arc_read: Arc<Mutex<UdpSocket>>, socket_arc_write: Arc<Mutex<UdpSocket>>, ongoing_session_list_arc: Arc<Mutex<SessionList>>, session_list_arc: Arc<Mutex<SessionList>>, tcp_port: i32, tcp_socket: TcpListener) -> CustomerService {
        CustomerService {
            db_arc: db_arc,
            socket_arc_read: socket_arc_read,
            socket_arc_write: socket_arc_write,
            ongoing_session_list_arc: ongoing_session_list_arc,
            session_list_arc: session_list_arc,
            tcp_port: tcp_port,
            tcp_socket: tcp_socket
        }
    }
    pub fn routine(&self) {
        loop {
            let mut buf = [0; 1024];
            let (amt, src): (usize, SocketAddr);
            {
                let socket = (&self.socket_arc_read).lock().unwrap();
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
                let mut encrypted_paket = pr.get_bytes(amt - 12);
                let session: Session;
                {
                    let session_list = &self.session_list_arc.lock().unwrap();
                    session = session_list.get_session(&session_id).clone();
                }
                let mut pr = PaketReader::from_encrypted(encrypted_paket.as_mut_slice(), &session.aes_dec);
                let cmd = pr.get_int();
                if cmd == EXIT_COMMAND {
                    self.exit_session(&session.session_id);
                } else if cmd == SHOW_BALANCE_COMMAND {
                    self.show_balance(&session, src);
                } else if cmd == TRANSFER_COMMAND {
                    self.transfer(&session, pr);
                } else if cmd == SEE_TURNOVER {
                    self.show_turnover(&session, src);
                }
            }
        }
    }

    fn start_login(&self, mut pr: PaketReader, src:&SocketAddr) {
        let email = pr.get_string().replace("\n", "");
        let res: (String, String);
        {
            let db = &self.db_arc.lock().unwrap();
            let res_opt = db.query_customer_from_email(&email);
            match res_opt {
                Ok(query_res) => res = query_res,
                Err(_err) => return,
            }
        }
    
        let mut session_key = to_fixed_len(create_random_id(32).as_bytes());
        let session = Session::new(create_random_id(8), res.0, session_key);
        let session_id = session.session_id.clone();
        {
            let _ = &self.ongoing_session_list_arc.lock().unwrap().insert(session);
        }

        let mut pb = PaketBuilder::new(48);
        pb.add_bytes(session_id.as_bytes());
        let password_hash = create_hashcode_sha256(&res.1);
        let len = (&session_key).len();
        let _ = Aes256CbcEnc::new((&password_hash).into(), (&IV).into()).encrypt_padded_mut::<NoPadding>(&mut session_key, len).unwrap();
        pb.add_bytes(&mut session_key);

        {
            let socket = &self.socket_arc_write.lock().unwrap();
            let _ = socket.send_to(&pb.get_paket(), src);
        }
    }

    fn complete_login(&self, pr: &mut PaketReader, src:&SocketAddr) {
        let received_session_id = pr.get_string_with_len(8);
        let session: Session;
        {
            let ongoing_session_list = &self.ongoing_session_list_arc.lock().unwrap();
            session = ongoing_session_list.get_session(&received_session_id).clone();
        }

        let received_password_hash = pr.get_bytes(32);
        let mut received_password_hash_fixed: [u8; 32] = to_fixed_len::<32>(&received_password_hash);
    
        //query customer password
        let queried_password: String;
        {
            let db = &self.db_arc.lock().unwrap();
            queried_password = db.query_customer_from_id(&session.customer_id).unwrap().1;
        }

        let queried_password_hash = create_hashcode_sha256(&queried_password);
        let _ = session.aes_dec.decrypt_padded_mut::<NoPadding>(&mut received_password_hash_fixed).unwrap();
        
        let session: Session;
        {
            let mut ongoing_session_list = &mut self.ongoing_session_list_arc.lock().unwrap();
            session = ongoing_session_list.remove_session(&received_session_id);
        }

        if queried_password_hash.iter().eq(&received_password_hash_fixed) {
            let socket = &self.socket_arc_write.lock().unwrap();
            let _ = socket.send_to(&int_to_u8(LOGIN_ACK), src);
            let mut session_list = &mut self.session_list_arc.lock().unwrap();
            session_list.insert(session);
        } else {
            let socket = &self.socket_arc_write.lock().unwrap();
            let _ = socket.send_to(&int_to_u8(LOGIN_NACK), src);
        }
    }

    fn exit_session(&self, session_id: &String) {
        let _ = self.session_list_arc.lock().unwrap().remove_session(session_id);
    }

    fn show_balance(&self, session: &Session, src: SocketAddr) {
        let balance: i32;
        {
            let db = &self.db_arc.lock().unwrap();
            balance = db.query_balance(&db.query_account_to_customer_from_id(&session.customer_id).unwrap());
        }
        let mut pb = PaketBuilder::new(16);
        pb.add_int(SHOW_BALANCE_RESPONSE);
        pb.add_int(balance);
        {
            let _ = &self.socket_arc_write.lock().unwrap().send_to(pb.get_encrypted(&session.aes_enc).iter().as_slice(), src);
        }
    }

    fn transfer(&self, session: &Session, mut pr: PaketReader) {
        let email = pr.get_string();
        let amount = pr.get_int();
        let reference = pr.get_string();
        let today= Local::now().date_naive();

        let db = self.db_arc.lock().unwrap();
        let account_id_sender = db.query_account_to_customer_from_id(&session.customer_id).unwrap();
        let account_id_receiver_res = db.query_account_to_customer_from_mail(&email);
        if account_id_receiver_res.is_err() {
            return;
        }
        let account_id_receiver = account_id_receiver_res.unwrap();

        let daily_closing_sender = db.query_daily_closing(&account_id_sender);
        let daily_closing_receiver = db.query_daily_closing(&account_id_receiver);
        let balance_sender: i32 = daily_closing_sender.2;
        if amount < 1 || account_id_receiver.eq(&account_id_sender) || reference.contains("'") || balance_sender - amount < 0 {
            return;
        }
        let balance_receiver: i32 = daily_closing_receiver.2;
        let new_balance_sender = balance_sender - amount;
        let new_balance_receiver = balance_receiver + amount;

        let sender_dailyclosing_date = NaiveDate::parse_from_str(&daily_closing_sender.3, DATE_FORMAT).unwrap();
        let receiver_dailyclosing_date = NaiveDate::parse_from_str(&daily_closing_sender.3, DATE_FORMAT).unwrap();

        db.create_transfer(MANUAL_TRANSFER, &account_id_sender, &account_id_receiver, amount, &reference);

        if sender_dailyclosing_date.eq(&today) {
            db.update_daily_closing(daily_closing_sender.0, new_balance_sender);
        } else {
            db.create_daily_closing(&account_id_sender, new_balance_sender);
        }

        if receiver_dailyclosing_date.eq(&today) {
            db.update_daily_closing(daily_closing_receiver.0, new_balance_receiver);
        } else {
            db.create_daily_closing(&account_id_receiver, new_balance_receiver);
        }
    }

    fn tcp_on_demand(&self, session: &Session, src: &SocketAddr) -> TcpStream {
        let mut pb = PaketBuilder::new(16);
        pb.add_int(SEE_TURNOVER_RESPONSE);
        pb.add_int(self.tcp_port);
        {
            let _ = &self.socket_arc_write.lock().unwrap().send_to(&pb.get_encrypted(&session.aes_enc), src);
        }
        let (tcp_socket, _tcp_src) = self.tcp_socket.accept().unwrap();
        tcp_socket
    }

    fn show_turnover(&self, session: &Session, src: SocketAddr) {
        let tcp_socket = self.tcp_on_demand(&session, &src);
        let turnover;
        {
            let db = &self.db_arc.lock().unwrap();
            turnover = db.query_turnover(&db.query_account_to_customer_from_id(&session.customer_id).unwrap())
        }
        
        let mut out = AesOutputStream::<AES_STREAMS_BUFFER_SIZE>::new(tcp_socket, session.aes_enc.clone());
        for item in turnover {
            out.write_int(item.0);
            out.write_string(&item.1);
            out.write_string(&item.2);
            out.write_int(item.3);
            out.write_string(&item.4);
            out.write_string(&item.5);
        }
        out.write_int(TERMINATION);
    }
}