use rusqlite::{Connection};

pub struct DbInterface{
    con: Connection,
}

impl DbInterface {
    pub fn new(url: String) -> rusqlite::Result<DbInterface> {
        let is_initiallized = std::fs::exists(&url).unwrap();
        let con = Connection::open(&url)?;
        let db = DbInterface {
            con: con,
        };
        if !is_initiallized {
            db.init_database();
        }
        Ok(db)
    }

    fn init_database(&self) {
            let cmd = std::fs::read_to_string("Server/src/SQL-Scripts/create_tables.sql").unwrap();
            self.con.execute_batch(&cmd).unwrap();
            let cmd = std::fs::read_to_string("Server/src/SQL-Scripts/create_example_customers.sql").unwrap();
            self.con.execute_batch(&cmd).unwrap();
    }

    pub fn query_customer_from_id(&self, customer_id: &String) -> (String, String) {
        let sql = "select customer_id, password from customer where customer_id = ?1;";
        self.query_customer(sql, customer_id)
    }
        

    pub fn query_customer_from_email(&self, email: &String) -> (String, String) {
        let sql = "select customer_id, password from customer where email = ?1;";
        self.query_customer(sql, email)
    }

    fn query_customer(&self, sql: &str, value: &String) -> (String, String) {
        let mut stmt = self.con.prepare(sql).unwrap();
        stmt.query_one([value], |row| {
            Ok((row.get(0)?, row.get(1)?))
        }).unwrap()
    }

    pub fn query_balance(&self, account_id: &String) -> i32 {
        let sql = "select balance from daily_closing where account_id = ?1 order by date desc;";
        let mut stmt = self.con.prepare(sql).unwrap();
        stmt.query_one([account_id], |row| {
            Ok(row.get(0)?)
        }).unwrap()
    }

    pub fn query_account_to_customer_from_id(&self, customer_id: &String) -> String {
        let sql = "select account_id from account a inner join customer c on a.customer_id == c.customer_id where c.customer_id = ?1;";
        self.query_account_to_customer(&sql, customer_id)
    }

    pub fn query_account_to_customer_from_mail(&self, mail: &String) -> String {
        let sql = "select account_id from account a inner join customer c on a.customer_id == c.customer_id where c.email = ?1;";
        self.query_account_to_customer(&sql, mail)
    }

    pub fn query_account_to_customer(&self, sql: &str, arg: &String) -> String {
        let mut stmt = self.con.prepare(sql).unwrap();
        stmt.query_one([arg], |row| {
            Ok(row.get(0)?)
        }).unwrap()
    }

    pub fn query_daily_closing(&self, account_id: &String) -> (i32, String, i32, String) {
        let sql = "select * from daily_closing where account_id = ?1 order by date desc;";
        let mut stmt = self.con.prepare(&sql).unwrap();
        stmt.query_one([account_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        }).unwrap()
    }

    pub fn create_daily_closing(&self, account_id: &String, new_balance: i32) {
        let sql = "insert into daily_closing values(NULL, ?1, ?2,(select date('now', 'localtime')))";
        let _ = self.con.execute(&sql, [account_id, &new_balance.to_string()]);
    }

    pub fn update_daily_closing(&self, closing_id: i32, new_balance: i32) {
        let sql = "update daily_closing set balance = ?2 where closing_id = ?1;";
        let _ = self.con.execute(&sql, [&closing_id.to_string(), &new_balance.to_string()]);
    }

    pub fn create_transfer(&self, transfer_type: i32, account_id_sender: &String, account_id_receiver: &String, amount: i32, reference: &String) {
        let sql = "insert into transfer values(NULL, ?1, ?2, ?3, ?4, (select datetime('now', 'localtime')), ?5);";
        let _ = self.con.execute(sql, [&transfer_type.to_string(), account_id_sender, account_id_receiver, &amount.to_string(), reference]);
    }
}