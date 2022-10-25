pub mod cursor;
#[cfg(test)]
mod tests {
    use crate::cursor::Cursor;

    #[test]
    fn use_a_cursor() {
        let mut crsr = Cursor::new("  \n\tdisplay(12);");
        crsr.skip_while(|c| c.is_whitespace());
        assert_eq!(crsr.bump(), Some('d'));
    }
}
