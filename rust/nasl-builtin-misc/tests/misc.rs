// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use chrono::Offset;

    use nasl_builtin_utils::Register;
    use nasl_interpreter::{CodeInterpreter, ContextBuilder};
    use nasl_syntax::NaslValue;
    use std::time::Instant;

    #[test]
    fn rand() {
        let code = r###"
        rand();
        rand();
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        let first = parser.next();
        let second = parser.next();
        assert!(matches!(first, Some(Ok(NaslValue::Number(_)))));
        assert!(matches!(second, Some(Ok(NaslValue::Number(_)))));
        assert_ne!(first, second);
    }

    #[test]
    fn get_byte_order() {
        let code = r###"
        get_byte_order();
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Boolean(_)))));
    }

    #[test]
    fn dec2str() {
        let code = r###"
        dec2str(num: 23);
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok("23".into())));
    }

    #[test]
    fn nasl_typeof() {
        let code = r#"
        typeof("AA");
        typeof(1);
        typeof('AA');
        typeof(make_array());
        d['test'] = 2;
        typeof(d);
        typeof(NULL);
        typeof(a);
        typeof(23,76);
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("string".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("int".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("data".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("array".into()))));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("array".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("undef".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("undef".into()))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("int".into()))));
    }

    #[test]
    fn isnull() {
        let code = r###"
        isnull(42);
        isnull(Null);
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(false))));
        assert_eq!(parser.next(), Some(Ok(NaslValue::Boolean(true))));
    }

    #[test]
    fn unixtime() {
        let code = r###"
        unixtime();
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert!(matches!(parser.next(), Some(Ok(NaslValue::Number(_)))));
    }

    #[test]
    fn gzip() {
        let code = r#"
        gzip(data: 'z', headformat: "gzip");
        gzip(data: 'z');
        "#;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 2, 0, 175, 119, 210, 98, 1, 0, 0, 0]
                    .into()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Data(
                [120, 156, 171, 2, 0, 0, 123, 0, 123].into()
            )))
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
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("z".into()))));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("gz".into()))));
        parser.next();
        assert_eq!(parser.next(), Some(Ok(NaslValue::String("ngz".into()))));
    }

    #[test]
    fn localtime() {
        let code = r###"
        a = localtime(1676900372, utc: TRUE);
        b = localtime(1676900372, utc: FALSE);
        c = localtime(utc: TRUE);
        d = localtime(utc: FALSE);
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);

        let offset = chrono::Local::now().offset().fix().local_minus_utc();
        let date_a = parser.next();
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

        let date_b = parser.next();
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

        let date_c = parser.next().unwrap().unwrap();
        let date_d = parser.next().unwrap().unwrap();
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
        let code = r###"
        mktime(sec: 01, min: 02, hour: 03, mday: 01, mon: 01, year: 1970);
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        let offset = chrono::Local::now().offset().fix().local_minus_utc();
        assert_eq!(
            parser.next(),
            Some(Ok(NaslValue::Number(10921 - offset as i64)))
        );
    }

    #[test]
    fn sleep() {
        let code = r###"
        sleep(1);
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        let now = Instant::now();
        parser.next();
        assert!(now.elapsed().as_secs() >= 1);
    }

    #[test]
    fn usleep() {
        let code = r###"
        usleep(1000);
        "###;
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        let now = Instant::now();
        parser.next();
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
        let register = Register::default();
        let binding = ContextBuilder::default();
        let context = binding.build();
        let mut parser = CodeInterpreter::new(code, register, &context);
        assert_eq!(parser.next(), Some(Ok(NaslValue::Null))); // defining function b
        assert_eq!(parser.next(), Some(Ok(true.into()))); // is b defined
        assert_eq!(parser.next(), Some(Ok(true.into()))); // is defined_func defined
        assert_eq!(parser.next(), Some(Ok(12i64.into()))); // defining variable a
        assert_eq!(parser.next(), Some(Ok(false.into()))); // is a a function
        assert_eq!(parser.next(), Some(Ok(false.into()))); // is the value of a a function
    }
}
