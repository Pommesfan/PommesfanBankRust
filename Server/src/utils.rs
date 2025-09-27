use random_string::generate;

pub fn create_random_id(n: i32) -> String {
    let charset = "1234567890";
    return generate(n as usize, charset);
}