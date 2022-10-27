pub mod cursor;
pub mod token;
#[cfg(test)]
mod tests {
    use crate::cursor::Cursor;

    #[test]
    fn use_a_cursor() {
        let mut cursor = Cursor::new("  \n\tdisplay(12);");
        cursor.skip_while(|c| c.is_whitespace());
        assert_eq!(cursor.advance(), Some('d'));
    }
}
