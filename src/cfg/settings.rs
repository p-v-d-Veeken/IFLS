#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum KeyEntropy {
    High,
    Medium,
    Low,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum HmacAlgorithm {
    HmacSha512,
    HmacSha256,
}
