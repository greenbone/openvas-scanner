// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::nasl::test_prelude::*;

#[test]
fn pem_to_rsa() {
    let mut t = TestBuilder::default();
    t.run(
        r#"k = string("-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIQ5CH/ufZZ1YCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDxmGK6wsNG+mJ2DrN7NvYMBIIE
0MOr915btKdR+AQUEIGaMjUbnvvIN1yCM/rNcwL1YFIsKQvjWS7e6aKKPgwbR2TX
wfficKJzSWTfe6XNv62fhWvG9XTwpjmNbbaIQnOhcThNV5t1XSqmkhCK73v+hVHk
NgHu838oCDx0aXg0wajtXYY3Av/agW0N67wrn4jaHnEv2WBsUhVFWdzSuKWXvtE1
Wf4fbT4CKrCjajZr1qkn5mtqvpdXHky/EnLBCMQR+TlcIVqt9hRoh6c/oJ2BMIo4
tuSychAnQkciGVrdJ7nRCTjy2L9p8umGApMTVb7hKf+sWc1bTJeucQaknTvl7KHE
SmGgO9dqVSmgKsKQLFrEdydzPiap4FUN+tFJhtOni7i0Z5BgqQ9ug6NbRhcquuy6
jO9qbepAr60zA2hbxIB04Hk/wzOYc1sibhLDXVUueIKfkG7H8hI78GuusyWtSjfK
NjUHhMj96YvAXffA0UYZB+CgopyFnpLqSwKLwnXlHwTLI1ThE94lZ7T2BDtr1i92
2MT8Og9DboSOxyXOk9slNkS7V7q8nWOQsA5UOk1PHpuy9Jo8xVR2hzCMLWq31HDl
ehSQch79+xIFfXdPolt+/E89soT/+zlsO/qVv2/Sxrh5rnphGcHjbtDb50zcQaqM
ZDsnT3i9Of0mKbVL2qpDOtFHMOuTKJ8LAqQA0NK9QP5V61ThZnwKRCm9EAilJJYr
OOdnfKoY/AP8aTFj2eLvnHtiJZgXDixTNWNImruiOQIVvZOgWzb8u07dcJxuUbLR
Kx7/MBKjQUM/M0ulMMBnNpXvY3jq1gLbesneAa7Dir9hIAB+C2rRGxjsWIHAU4fe
g4r35GKBahH3eRn+fO0V1ADmb/hGG0IBFmaNRFeigWM6y/9A+7auG4ekYk92QlY3
bwYtTItSir8Bu9dgXKkmP13wQqGGEVFcb30TdSPxOyXOeVf5aYZnMXOE3fATgVDm
ahYU7WyMQEGNS2v+6V3qXc5H0ufw3zrr9WmCo5W41ysCA9lR40H1LHj634FP+B8F
Mt7ld5SZKKv9LSqbgUq1VCmtDI4lVc6ZRh2NTM3Fo6xcdWFokLE/9rF1uJJbsHFe
L5rsARd+jR4r9EAUsJup1G+1nazlUGH+J8BWIjwc9IQ9q93l6Bq0XU/udm7BCOnx
xcl6mNgYo7d5NVXw5x8qXN6bhEu43Ldc7H83UOTN+ZhVPoyxHS0Tvj0RxKrl1FVo
wE26DVTGoEEYROpGL8uOmUE/2Jvsdy+bu3jfv9plCMk2UkUuXW5q4uPv71P/rN9z
RBI4ChVTW22I9Aev/wXIgnE5wtC3sKZwhoZMmdYmVrAeF0ExrtUs336soQ76/Kyu
UXAzxzKBlSz1POjo6qvDCJkolAuDmn4pIM6vHC1nBymJ2UC4Xlrh6b8fkj/850Ef
au1Me6WvHqTKUzt2pyvsWevUtWBmLe8GytUkpbqDk7btH79QqV7k3dUa1BAPyz1m
NONWZ1afBY6ihkjvTVkpBoQ01LUHofM4C/x8Wc2zxu76fwguv5O2XkWcmWR2y78a
dS5gDp+SO20D9RkTiLKSBTtDh7kNlebT3wAAWaVAvDFmny6uu86PGNGEKv+ZeBtQ
4CTCN2401TE896U9S6k6+T3kWY38epf2X4TyBqUXn1tC
-----END ENCRYPTED PRIVATE KEY-----");"#,
    );

    t.ok(
        r#"pem_to_rsa(priv:k, passphrase: "1234");"#,
        vec![
            6u8, 30, 162, 22, 83, 189, 220, 100, 5, 235, 27, 43, 223, 38, 220, 250, 128, 74, 29,
            252, 132, 107, 207, 195, 2, 211, 29, 152, 191, 140, 115, 220, 167, 83, 31, 142, 233,
            77, 11, 201, 10, 150, 83, 76, 163, 6, 39, 245, 190, 21, 213, 84, 115, 204, 51, 195,
            249, 252, 100, 228, 112, 70, 200, 193, 136, 114, 243, 93, 59, 45, 133, 40, 161, 106,
            96, 44, 73, 189, 187, 31, 103, 175, 103, 85, 251, 76, 234, 159, 157, 110, 10, 125, 81,
            87, 134, 94, 236, 156, 209, 221, 3, 0, 240, 81, 209, 215, 8, 100, 34, 16, 96, 215, 14,
            142, 116, 203, 7, 219, 44, 228, 129, 32, 96, 21, 236, 118, 205, 11, 28, 137, 225, 200,
            236, 244, 23, 152, 200, 136, 70, 254, 96, 150, 131, 121, 7, 12, 175, 180, 63, 5, 199,
            200, 108, 58, 197, 84, 127, 49, 60, 202, 108, 161, 211, 185, 252, 139, 226, 85, 216,
            133, 67, 222, 31, 79, 5, 245, 40, 40, 225, 81, 72, 159, 241, 7, 254, 226, 174, 89, 196,
            106, 125, 116, 6, 10, 243, 112, 62, 226, 162, 243, 172, 143, 106, 99, 185, 97, 10, 34,
            181, 192, 120, 106, 182, 145, 151, 150, 143, 11, 178, 86, 93, 79, 189, 189, 16, 133,
            34, 118, 204, 2, 145, 78, 206, 24, 4, 38, 0, 166, 43, 187, 175, 194, 37, 102, 57, 252,
            23, 47, 248, 209, 119, 71, 59, 196, 103, 53,
        ],
    );
}
#[test]
fn pem_to_dsa() {
    let mut t = TestBuilder::default();
    t.run(
        r#"k= string("-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIBOez9g3GT4ECAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEWBBBj0hLfDRlNoOZ1NuFQYkZ0BIIB
YPtxXL1LQ0sZW5iAXysaXDydTBzY4G99m9WwGWZtnv2S8FRqUhPohB1Kk/PDoFYH
IxtF2pGjhAEW7IQrTk881IVKamGqoZyq5VkBttCOTr1kQgL+PZx9mjaIWvrb6qt/
ygdkk0mq4pLm4PkIS5StXQLE8MSPkfG9rtf5ngQIxy0vHix1IcYx7qebPJY3ezjq
jXSARCzQBhIvVMNyKd10f6A3w5vPVykrquglrF/bJRuOZH/5wXgmoyo+uhuVjin9
ad72GGysPhQU1kw4BIuDI8zVMgrRfGegs8ubWDI/+kpBo5AK0Nedq8DKtXDdKwDp
zbV5Nq6RqhcVmYIS44CY9U6Dl38IHRrDQ4JOZFo6PtaicqHWnWXmRq7kDhvHiLOL
qsgN3/1DoY68oUIHHIHX2lLr6+FQtD6kV+1Cmd2Nkx/Dx14vJxWtgeV1R1UkTcOI
mTUpbA6OC8q4ZgKc0n063gw=
-----END ENCRYPTED PRIVATE KEY-----");"#,
    );

    t.ok(
        r#"pem_to_dsa(priv:k, passphrase: "1234");"#,
        vec![
            188u8, 115, 157, 10, 3, 168, 206, 164, 92, 141, 156, 190, 235, 90, 237, 212, 123, 27,
            190, 106, 183, 6, 209, 234, 67, 185, 21, 10,
        ],
    );
}
