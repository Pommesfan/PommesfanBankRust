use rusqlite::{Connection};

pub struct DbInterface{
    con: Connection,
}

pub struct QueryResCustomer {
    pub customer_id: String,
    pub password: String,
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

    pub fn query_customer(&self, attr: String, value: &String) -> QueryResCustomer {
        let mut sql = String::from("select customer_id, password from customer where ");
        sql.push_str(&attr);
        sql.push_str(" = '");
        sql.push_str(value);
        sql.push_str("';");
        let mut stmt = self.con.prepare(&sql).unwrap();

        stmt.query_one([], |row| {
            Ok(QueryResCustomer {
                customer_id: row.get(0)?,
                password: row.get(1)?
            })
        }).unwrap()
    }

    pub fn query_balance(&self, account_id: &String) -> i32 {
        let sql = String::from("select balance from daily_closing where account_id = ?1 order by date desc;");
        let mut stmt = self.con.prepare(&sql).unwrap();
        stmt.query_one([account_id], |row| {
            Ok(row.get(0)?)
        }).unwrap()
    }

    pub fn query_account_to_customer(&self, customer_id: &String) -> String {
        let sql = String::from("select account_id from account a inner join customer c on a.customer_id == c.customer_id where c.customer_id = ?1");
        let mut stmt = self.con.prepare(&sql).unwrap();
        stmt.query_one([customer_id], |row| {
            Ok(row.get(0)?)
        }).unwrap()
    }
}