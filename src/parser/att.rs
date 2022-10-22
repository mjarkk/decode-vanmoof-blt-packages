use super::Bytes;

pub struct Att {}

impl Att {
    pub fn parse(_b: &Bytes, _attribute_protocol: u16, _nr: usize) -> Option<Self> {
        println!("att: {}", _nr);
        None
    }
}
