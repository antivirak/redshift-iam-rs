// inspired by github.com/aws/amazon-redshift-python-driver
// provides saml and IAM temp credential login

#[doc(hidden)]
pub mod iam_provider;
#[doc(hidden)]
pub mod redshift;
pub mod saml_provider;

pub(crate) mod re {
    use regex::Regex;

    pub fn compile(pattern: &str) -> Regex {
        Regex::new(pattern).unwrap()
    }
}

// Re-export public API at crate root so structs and traits appear at the
// top level in docs and can be imported as `redshift_iam::PingCredentialsProvider`.
pub use iam_provider::IamProvider;
pub use redshift::Redshift;
pub use saml_provider::{PingCredentialsProvider, SamlProvider};

#[doc(hidden)]
pub mod prelude {
    pub use crate::iam_provider::IamProvider;
    pub use crate::redshift::Redshift;
    pub use crate::saml_provider::PingCredentialsProvider;
}
