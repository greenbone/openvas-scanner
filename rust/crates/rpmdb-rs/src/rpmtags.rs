// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
pub(crate) const RPMTAG_HEADERIMAGE: i32 = 61;
pub(crate) const RPMTAG_HEADERSIGNATURES: i32 = 62;
pub(crate) const RPMTAG_HEADERIMMUTABLE: i32 = 63;
pub(crate) const HEADER_I18NTABLE: i32 = 100;
pub(crate) const RPMTAG_HEADERI18NTABLE: i32 = HEADER_I18NTABLE;

// rpmTag_e
// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
pub(crate) const RPMTAG_NAME: u32 = 1000;
pub(crate) const RPMTAG_VERSION: u32 = 1001;
pub(crate) const RPMTAG_RELEASE: u32 = 1002;
pub(crate) const RPMTAG_EPOCH: u32 = 1003;
pub(crate) const RPMTAG_INSTALLTIME: u32 = 1008;
pub(crate) const RPMTAG_SIZE: u32 = 1009;
pub(crate) const RPMTAG_VENDOR: u32 = 1011;
pub(crate) const RPMTAG_LICENSE: u32 = 1014;
pub(crate) const RPMTAG_ARCH: u32 = 1022;
pub(crate) const RPMTAG_FILESIZES: u32 = 1028;
pub(crate) const RPMTAG_FILEMODES: u32 = 1030;
pub(crate) const RPMTAG_FILEDIGESTS: u32 = 1035;
pub(crate) const RPMTAG_FILEFLAGS: u32 = 1037;
pub(crate) const RPMTAG_FILEUSERNAME: u32 = 1039;
pub(crate) const RPMTAG_FILEGROUPNAME: u32 = 1040;
pub(crate) const RPMTAG_SOURCERPM: u32 = 1044;
pub(crate) const RPMTAG_PROVIDENAME: u32 = 1047;
pub(crate) const RPMTAG_REQUIRENAME: u32 = 1049;
pub(crate) const RPMTAG_DIRINDEXES: u32 = 1116;
pub(crate) const RPMTAG_BASENAMES: u32 = 1117;
pub(crate) const RPMTAG_DIRNAMES: u32 = 1118;

// rpmTag_enhances
// https://github.com/rpm-software-management/rpm/blob/rpm-4.16.0-release/lib/rpmtag.h#L375
pub(crate) const RPMTAG_MODULARITYLABEL: u32 = 5096;

// rpmTagType_e
// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L431
pub(crate) const RPM_MIN_TYPE: u32 = 0;
pub(crate) const RPM_NULL_TYPE: u32 = 0;
pub(crate) const RPM_CHAR_TYPE: u32 = 1;
pub(crate) const RPM_INT8_TYPE: u32 = 2;
pub(crate) const RPM_INT16_TYPE: u32 = 3;
pub(crate) const RPM_INT32_TYPE: u32 = 4;
pub(crate) const RPM_INT64_TYPE: u32 = 5;
pub(crate) const RPM_STRING_TYPE: u32 = 6;
pub(crate) const RPM_BIN_TYPE: u32 = 7;
pub(crate) const RPM_STRING_ARRAY_TYPE: u32 = 8;
pub(crate) const RPM_I18NSTRING_TYPE: u32 = 9;
pub(crate) const RPM_MAX_TYPE: u32 = 9;
