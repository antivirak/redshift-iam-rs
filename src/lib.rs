// inspired by github.com/aws/amazon-redshift-python-driver
// provides saml and IAM temp credential login

pub mod iam_provider;
pub mod redshift;
pub mod saml_provider;

pub mod re {
    use regex::Regex;

    pub fn compile(pattern: &str) -> Regex {
        Regex::new(pattern).unwrap()
    }
}

pub mod prelude {
    pub use crate::iam_provider::IamProvider;
    pub use crate::redshift::Redshift;
    pub use crate::saml_provider::PingCredentialsProvider;
}
