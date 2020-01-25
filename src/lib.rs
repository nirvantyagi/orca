mod algmac;
//pub mod groupsig;

pub type Error = Box<dyn std::error::Error>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
