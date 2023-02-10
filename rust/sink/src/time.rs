pub trait AsUnixTimeStamp {
    fn as_timestamp(&self) -> Option<i64>;
}

use time::macros::format_description;
use time::OffsetDateTime;

// for more information see:
// https://time-rs.github.io/book/api/format-description.html
const SUPPORTED_FORMATS: &[&[time::format_description::FormatItem]] = &[
    format_description!(
       "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour][offset_minute]"
    ),
    format_description!(
       "[weekday repr:short] [month repr:short] [day] [hour]:[minute]:[second] [year] [offset_hour][offset_minute]"
    ),
    format_description!(
       "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] [offset_hour][offset_minute]"
    ),
];

impl AsUnixTimeStamp for &str {
    fn as_timestamp(&self) -> Option<i64> {
        let to_parse = {
            // transforms `$Date: wanted (....) $` to wanted
            self.splitn(2, "$Date: ")
                .filter_map(|x| x.split(" $").next())
                .filter_map(|x| x.split(" (").next())
                .find(|x| !x.is_empty())
                .unwrap_or_default()
        };
        SUPPORTED_FORMATS
            .iter()
            .filter_map(|x| OffsetDateTime::parse(to_parse, x).ok())
            .map(|x| x.unix_timestamp())
            .next()
    }
}

#[cfg(test)]
mod tests {
    use super::AsUnixTimeStamp;

    #[test]
    fn date_string() {
        let example = "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $";
        assert_eq!(example.as_timestamp(), Some(1536311311));
    }

    #[test]
    fn iso_orientated() {
        let example = "2012-09-23 02:15:34 -0400";
        assert_eq!(example.as_timestamp(), Some(1348380934));
        let example = "2012-09-23 02:15:34 +0400";
        assert_eq!(example.as_timestamp(), Some(1348352134));
    }

    #[test]
    fn something_else() {
        let example = "Fri Feb 10 16:09:30 2023 +0100";
        assert_eq!(example.as_timestamp(), Some(1676041770));
        let example = "Fri, 10 Feb 2023 16:09:30 +0100";
        assert_eq!(example.as_timestamp(), Some(1676041770));
    }
}
