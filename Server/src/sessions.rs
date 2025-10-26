use std::collections::BTreeMap;
use common::utils::IV;
use aes::cipher::KeyIvInit;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub struct Session {
    pub session_id: String,
    pub customer_id: String,
    pub aes_enc: Aes256CbcEnc,
    pub aes_dec: Aes256CbcDec,
}

impl Session {
    pub fn new(p_session_id: String, p_customer_id: String, p_session_crypto: [u8; 32]) -> Session {
        Session{
            session_id: p_session_id,
            customer_id: p_customer_id,
            aes_enc: Aes256CbcEnc::new((&p_session_crypto).into(), (&IV).into()),
            aes_dec: Aes256CbcDec::new((&p_session_crypto).into(), (&IV).into()),
        }
    }
}

impl Clone for Session {
    fn clone(&self) -> Session {
        Session {
            session_id: self.session_id.clone(),
            customer_id: self.customer_id.clone(),
            aes_enc: self.aes_enc.clone(),
            aes_dec: self.aes_dec.clone()
        }
    }
}

pub struct SessionList {
    map: BTreeMap<String, Session>,
}

impl SessionList {
    pub fn new() ->SessionList {
        SessionList {
            map: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, s: Session) {
        self.map.insert(s.session_id.clone(), s);
    }

    pub fn get_session(&self, session_id: &String) -> &Session {
        self.map.get(session_id).unwrap()
    }

    pub fn remove_session(&mut self, session_id: &String) -> Session{
        self.map.remove(session_id).unwrap()
    }
}