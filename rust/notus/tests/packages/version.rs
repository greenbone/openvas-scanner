#[cfg(test)]
mod tests {
    use notus::packages::PackageVersion;

    #[test]
    fn test_version_1() {
        let v1 = PackageVersion("1.2.3");
        let v2 = PackageVersion("1.2.12");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_2() {
        let v1 = PackageVersion("1.2.3");
        let v2 = PackageVersion("1.2.3~rc");

        assert!(v1 > v2);
    }

    #[test]
    fn test_version_3() {
        let v1 = PackageVersion("1.2.3");
        let v2 = PackageVersion("1.2.3");

        assert!(v1 == v2);
    }

    #[test]
    fn test_version_4() {
        let v1 = PackageVersion("1.2.3");
        let v2 = PackageVersion("1.2.3a");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_5() {
        let v1 = PackageVersion("1.2.3a");
        let v2 = PackageVersion("1.2.3b");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_6() {
        let v1 = PackageVersion("1.2.3a");
        let v2 = PackageVersion("1.2.3-2");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_7() {
        let v1 = PackageVersion("1.2");
        let v2 = PackageVersion("1.2.3");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_8() {
        let v1 = PackageVersion("1.2.3.1");
        let v2 = PackageVersion("1.2.3_a");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_9() {
        let v1 = PackageVersion("1.2.3_a");
        let v2 = PackageVersion("1.2.3_1");

        assert!(v1 < v2);
    }

    #[test]
    fn test_version_10() {
        let v1 = PackageVersion("20211016ubuntu0.20.04.1");
        let v2 = PackageVersion("20211016~20.04.1");

        assert!(v1 > v2);
    }
}
