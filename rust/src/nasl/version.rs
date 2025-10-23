#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub enum NaslVersion {
    #[default]
    V1,
    #[allow(unused)]
    V2,
}
