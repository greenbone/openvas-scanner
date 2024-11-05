// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use chrono::Offset;

    use crate::nasl::test_prelude::*;

    use std::time::Instant;

    #[test]
    fn rand() {
        check_code_result_matches!("rand();", NaslValue::Number(_));
        check_code_result_matches!("rand();", NaslValue::Number(_));
    }

    #[test]
    fn get_byte_order() {
        check_code_result_matches!("get_byte_order();", NaslValue::Boolean(_));
    }

    #[test]
    fn dec2str() {
        check_code_result("dec2str(num: 23);", "23");
    }

    #[test]
    fn nasl_typeof() {
        let mut t = TestBuilder::default();
        t.ok(r#"typeof("AA");"#, "string");
        t.ok(r#"typeof(1);"#, "int");
        t.ok(r#"typeof('AA');"#, "data");
        t.ok(r#"typeof(make_array());"#, "array");
        t.ok(r#"typeof(NULL);"#, "undef");
        t.ok(r#"typeof(a);"#, "undef");
        check_err_matches!(
            t,
            r#"typeof(23,76);"#,
            ArgumentError::TrailingPositionals { .. }
        );
        t.ok("d['test'] = 2;", 2);
        t.ok("typeof(d);", "array");
    }

    #[test]
    fn isnull() {
        check_code_result(r#"isnull(42);"#, false);
        check_code_result(r#"isnull(Null);"#, true);
    }

    #[test]
    fn unixtime() {
        check_code_result_matches!(r#"unixtime();"#, NaslValue::Number(_));
    }

    #[test]
    fn gzip() {
        check_code_result(
            r#"gzip(data: 'z', headformat: "gzip");"#,
            vec![
                31u8, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 2, 0, 175, 119, 210, 98, 1, 0, 0, 0,
            ],
        );
        check_code_result(
            r#"gzip(data: 'z');"#,
            vec![120u8, 156, 171, 2, 0, 0, 123, 0, 123],
        );
    }

    #[test]
    fn gunzip() {
        let mut t = TestBuilder::default();
        t.run(r#"z = raw_string (0x78, 0x9c, 0xab, 0x02, 0x00, 0x00, 0x7b, 0x00, 0x7b);"#);
        t.ok(r#"gunzip(data: z);"#, "z");
        t.run(r#"gz = gzip(data: 'gz', headformat: "gzip");"#);
        t.ok(r#"gunzip(data: gz);"#, "gz");
        t.run(r#"ngz = gzip(data: "ngz");"#);
        t.ok(r#"gunzip(data: ngz);"#, "ngz");
    }

    #[test]
    fn localtime() {
        let mut t = TestBuilder::default();
        t.run_all(
            r#"
            a = localtime(1676900372, utc: TRUE);
            b = localtime(1676900372, utc: FALSE);
            c = localtime(utc: TRUE);
            d = localtime(utc: FALSE);
        "#,
        );
        let results = t.results();
        let mut results = results.into_iter();

        let offset = chrono::Local::now().offset().fix().local_minus_utc();
        let date_a = results.next();
        assert!(matches!(date_a, Some(Ok(NaslValue::Dict(_)))));
        match date_a.unwrap().unwrap() {
            NaslValue::Dict(x) => {
                assert_eq!(x["sec"], NaslValue::Number(32));
                assert_eq!(x["min"], NaslValue::Number(39));
                assert_eq!(x["hour"], NaslValue::Number(13));
                assert_eq!(x["mday"], NaslValue::Number(20));
                assert_eq!(x["mon"], NaslValue::Number(2));
                assert_eq!(x["year"], NaslValue::Number(2023));
                assert_eq!(x["wday"], NaslValue::Number(1));
                assert_eq!(x["yday"], NaslValue::Number(51));
                assert_eq!(x["isdst"], NaslValue::Number(0));
            }
            _ => panic!("NO DICT"),
        }

        let date_b = results.next();
        assert!(matches!(date_b, Some(Ok(NaslValue::Dict(_)))));
        match date_b.unwrap().unwrap() {
            NaslValue::Dict(x) => {
                assert_eq!(x["sec"], NaslValue::Number(32));
                assert_eq!(x["min"], NaslValue::Number(39));
                assert_eq!(x["hour"], NaslValue::Number(13 + (offset / 3600) as i64));
                assert_eq!(x["mday"], NaslValue::Number(20));
                assert_eq!(x["mon"], NaslValue::Number(2));
                assert_eq!(x["year"], NaslValue::Number(2023));
                assert_eq!(x["wday"], NaslValue::Number(1));
                assert_eq!(x["yday"], NaslValue::Number(51));
                assert_eq!(x["isdst"], NaslValue::Number(0));
            }
            _ => panic!("NO DICT"),
        }

        let date_c = results.next().unwrap().unwrap();
        let date_d = results.next().unwrap().unwrap();
        let hour_c: i64;
        let hour_d: i64;
        let min_c: i64;
        let min_d: i64;
        match date_c {
            NaslValue::Dict(x) => {
                hour_c = i64::from(x["hour"].to_owned());
                min_c = i64::from(x["min"].to_owned());
            }
            _ => panic!("NO DICT"),
        }
        match date_d {
            NaslValue::Dict(x) => {
                hour_d = i64::from(x["hour"].to_owned());
                min_d = i64::from(x["min"].to_owned());
            }
            _ => panic!("NO DICT"),
        }
        assert_eq!(
            hour_c * 60 + min_c,
            hour_d * 60 + min_d - (offset / 60) as i64
        );
    }

    #[test]
    fn mktime() {
        let offset = chrono::Local::now().offset().fix().local_minus_utc();
        check_code_result(
            r#"mktime(sec: 01, min: 02, hour: 03, mday: 01, mon: 01, year: 1970);"#,
            10921 - offset,
        );
    }

    #[test]
    fn sleep() {
        let now = Instant::now();
        check_code_result(r#"sleep(1);"#, NaslValue::Null);
        assert!(now.elapsed().as_secs() >= 1);
    }

    #[test]
    fn usleep() {
        let now = Instant::now();
        check_code_result(r#"usleep(1000);"#, NaslValue::Null);
        assert!(now.elapsed().as_micros() >= 1000);
    }

    #[test]
    fn defined_func() {
        let mut t = TestBuilder::default();
        t.ok("function b() { return 2; }", NaslValue::Null);
        t.ok(r#"defined_func("b");"#, true);
        t.ok(r#"defined_func("defined_func");"#, true);
        t.ok("a = 12;", 12i64);
        t.ok(r#"defined_func("a");"#, false);
        t.ok("defined_func(a);", false);
    }
}
