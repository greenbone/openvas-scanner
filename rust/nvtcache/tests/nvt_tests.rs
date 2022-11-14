use nvtcache::nvt::Nvt;

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_nvt() {
        let mut nvt;
        let res = Nvt::new();

        match res {
            Ok(ok) => nvt = ok,
            Err(_) => panic!("No Nvt"),
        }
        //Add first tag
        match nvt.add_tag("Tag Name".to_string(), "Tag Value".to_string()) {
            Ok(_) => (),
            Err(e) => println!("Error:{}", e),
        }
        match nvt.get_tag() {
            Ok(tag) => {
                assert_eq!(tag, "Tag Name=Tag Value");
            }
            Err(e) => println!("Error:{}", e),
        }
        //Add second tag
        match nvt.add_tag("Tag Name1".to_string(), "Tag Value1".to_string()) {
            Ok(_) => (),
            Err(e) => println!("Error:{}", e),
        }
        match nvt.get_tag() {
            Ok(tag) => {
                assert_eq!(tag, "Tag Name=Tag Value|Tag Name1=Tag Value1");
            }
            Err(e) => println!("Error:{}", e),
        }
    }
}
