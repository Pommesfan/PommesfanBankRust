create table customer(customer_id primary key, customer_name, email, password);

create table account(account_id primary key, customer_id,
foreign key(customer_id) references customer(customer_id));

create table transfer(transfer_id integer primary key autoincrement, transfer_type integer, account_from, account_to,
amount integer, date, reference,
foreign key(account_from) references account(account_id), foreign key(account_to) references account(account_id));

create table terminal(terminal_id primary key, terminal_key, account_id,
foreign key(account_id) references account(account_id));

create table debit_card(card_number primary key, card_key varbinary(64), customer_id,
foreign key(customer_id) references customer(customer_id));

create table daily_closing(closing_id integer primary key autoincrement, account_id, balance integer, date,
foreign key(account_id) references account(account_id));

create table card_payment(id integer primary key autoincrement, transfer_id integer, card_number, transfer_code,
foreign key(transfer_id) references transfer(transfer_id), foreign key(card_number) references debit_card(card_number));
