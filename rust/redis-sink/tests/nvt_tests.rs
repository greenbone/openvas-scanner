// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use redis_sink::dberror::RedisSinkResult;
use redis_sink::nvt::{parse_nvt_timestamp, Nvt};

#[cfg(test)]
mod test {

    use sink::nvt::{NvtRef, ACT};

    use super::*;

    #[test]
    fn test_tags() {
        let mut nvt;
        let res = Nvt::new();

        match res {
            Ok(ok) => nvt = ok,
            Err(_) => panic!("No Nvt"),
        }
        //Add first tag
        nvt.add_tag("Tag Name".to_string(), "Tag Value".to_string());
        let tag = nvt.tag();
        let expected = vec![("Tag Name".to_string(), "Tag Value".to_string())];
        assert_eq!(tag, &expected);

        //Add second tag cvss_base which is ignored
        nvt.add_tag("cvss_base".to_string(), "Tag Value1".to_string());
        let tag = nvt.tag();
        let expected = vec![("Tag Name".to_string(), "Tag Value".to_string())];

        assert_eq!(tag, &expected);
    }

    #[test]
    fn test_timestamp_converter() {
        let t = "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)";
        assert_eq!(parse_nvt_timestamp(t), 1312870834);

        let t = "$Date: 2012-02-17 16:05:26 +0100 (Fr, 17. Feb 2012) $";
        assert_eq!(parse_nvt_timestamp(t), 1329491126);

        let t = "$Date: Fri, 11 Nov 2011 14:42:28 +0100 $";
        assert_eq!(parse_nvt_timestamp(t), 1321018948);

        //Space left at the end. Fails and 0
        let t = "$Date: Fri, 11 Nov 2011 14:42:28 +0100 ";
        assert_eq!(parse_nvt_timestamp(t), 0);
    }

    #[test]
    fn test_bid_refs() -> RedisSinkResult<()> {
        let mut nvt = Nvt::new()?;
        let bid_refs1 = NvtRef::new(
            "bid".to_owned(),
            "BID_ID1".to_owned(),
            Some("BID-text".to_owned()),
        );
        let bid_refs2 = NvtRef::new(
            "bid".to_owned(),
            "BID_ID2".to_owned(),
            Some("BID-text".to_owned()),
        );

        nvt.add_ref(bid_refs1);
        nvt.add_ref(bid_refs2);
        let bid;
        (_, bid, _) = nvt.refs();

        assert_eq!(bid, "BID_ID1, BID_ID2");

        Ok(())
    }
    #[test]
    fn test_cve_refs() -> RedisSinkResult<()> {
        let mut nvt = Nvt::new()?;
        let cve_refs1 = NvtRef::new(
            "cve".to_owned(),
            "cve_ID1".to_owned(),
            Some("CVE-text".to_owned()),
        );
        let cve_refs2 = NvtRef::new(
            "cve".to_owned(),
            "cve_ID1".to_owned(),
            Some("CVE-text".to_owned()),
        );
        nvt.add_ref(cve_refs1);
        nvt.add_ref(cve_refs2);
        let cve;
        (cve, _, _) = nvt.refs();
        assert_eq!(cve, "cve_ID1, cve_ID1");

        Ok(())
    }
    #[test]
    fn test_xrefs() -> RedisSinkResult<()> {
        let mut nvt = Nvt::new()?;
        let xrefs1 = NvtRef::new(
            "URL".to_owned(),
            "http://greenbone.net".to_owned(),
            Some("some text".to_owned()),
        );
        let xrefs2 = NvtRef::new(
            "URL".to_owned(),
            "http://openvas.net".to_owned(),
            Some("some text".to_owned()),
        );

        nvt.add_ref(xrefs1);
        nvt.add_ref(xrefs2);
        let xrefs;
        (_, _, xrefs) = nvt.refs();
        assert_eq!(xrefs, "http://greenbone.net:URL, http://openvas.net:URL");

        Ok(())
    }

    #[test]
    fn test_category_from_trait() {
        let cat = ACT::End;

        assert_eq!(cat as i32, 10);
    }
}
