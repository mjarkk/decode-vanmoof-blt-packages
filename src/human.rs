pub fn human_u8_list(bytes: &Vec<u8>) -> String {
    to_hex(bytes).join(" ")
}

pub fn to_hex(bytes: &Vec<u8>) -> Vec<String> {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
    // let mut response = String::new();
    // for b in bytes {
    //     response = format!("{:02x}{}", b, response)
    // }
    // response
}
