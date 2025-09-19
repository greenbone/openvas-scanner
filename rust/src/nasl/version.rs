#[derive(Clone, Copy, Default, Debug)]
pub enum NaslVersion {
    #[default]
    V1,
    #[allow(unused)]
    V2,
}
