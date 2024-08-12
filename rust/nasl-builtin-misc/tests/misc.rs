// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use chrono::Offset;

    use nasl_interpreter::{
        check_err_matches, check_ok_matches,
        test_utils::{check_multiple, check_ok, run},
        FunctionErrorKind,
    };
    use nasl_syntax::NaslValue;
    use std::time::Instant;

    #[test]
    fn rand() {
        check_ok_matches!("rand();", NaslValue::Number(_));
        check_ok_matches!("rand();", NaslValue::Number(_));
    }

    #[test]
    fn get_byte_order() {
        check_ok_matches!("get_byte_order();", NaslValue::Boolean(_));
    }

    #[test]
    fn dec2str() {
        check_ok("dec2str(num: 23);", "23");
    }

    #[test]
    fn nasl_typeof() {
        check_ok(r#"typeof("AA");"#, "string");
        check_ok(r#"typeof(1);"#, "int");
        check_ok(r#"typeof('AA');"#, "data");
        check_ok(r#"typeof(make_array());"#, "array");
        check_ok(r#"typeof(NULL);"#, "undef");
        check_ok(r#"typeof(a);"#, "undef");
        check_err_matches!(
            r#"typeof(23,76);"#,
            FunctionErrorKind::TrailingPositionalArguments { .. }
        );
        check_multiple(
            "d['test'] = 2; typeof(d);",
            vec![NaslValue::from(2), NaslValue::from("array")],
        )
    }

    #[test]
    fn isnull() {
        check_ok(r#"isnull(42);"#, false);
        check_ok(r#"isnull(Null);"#, true);
    }

    #[test]
    fn unixtime() {
        check_ok_matches!(r#"unixtime();"#, NaslValue::Number(_));
    }

    #[test]
    fn gzip() {
        check_ok(
            r#"gzip(data: 'z', headformat: "gzip");"#,
            vec![
                31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 2, 0, 175, 119, 210, 98, 1, 0, 0, 0,
            ],
        );
        check_ok(
            r#"gzip(data: 'z');"#,
            vec![120, 156, 171, 2, 0, 0, 123, 0, 123],
        );
    }

    #[test]
    fn gunzip() {
        let code = r#"
        z = raw_string (0x78, 0x9c, 0xab, 0x02, 0x00, 0x00, 0x7b, 0x00, 0x7b);
        gunzip(data: z);
        # With Header Format and data is data
        gz = gzip(data: 'gz', headformat: "gzip");
        gunzip(data: gz);
        # Without Header format and data is a string
        ngz = gzip(data: "ngz");
        gunzip(data: ngz);
        "#;
        let results = run(code);
        assert_eq!(results[1], Ok(NaslValue::String("z".into())));
        assert_eq!(results[3], Ok(NaslValue::String("gz".into())));
        assert_eq!(results[5], Ok(NaslValue::String("ngz".into())));
    }

    #[test]
    fn localtime() {
        let code = r###"
        a = localtime(1676900372, utc: TRUE);
        b = localtime(1676900372, utc: FALSE);
        c = localtime(utc: TRUE);
        d = localtime(utc: FALSE);
        "###;
        let results = run(code);
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
        check_ok(
            r#"mktime(sec: 01, min: 02, hour: 03, mday: 01, mon: 01, year: 1970);"#,
            10921 - offset,
        );
    }

    #[test]
    fn sleep() {
        let now = Instant::now();
        check_ok(r#"sleep(1);"#, NaslValue::Null);
        assert!(now.elapsed().as_secs() >= 1);
    }

    #[test]
    fn usleep() {
        let now = Instant::now();
        check_ok(r#"usleep(1000);"#, NaslValue::Null);
        assert!(now.elapsed().as_micros() >= 1000);
    }

    #[test]
    fn defined_func() {
        let code = r#"
        function b() { return 2; }
        defined_func("b");
        defined_func("defined_func");
        a = 12;
        defined_func("a");
        defined_func(a);
        "#;
        check_multiple(
            code,
            vec![
                NaslValue::Null, // defining function b
                true.into(),     // is b defined
                true.into(),     // is defined_func defined
                12i64.into(),    // defining variable a
                false.into(),    // is a a function
                false.into(),    // is the value of a a function
            ],
        )
    }
}
