// inspired by github.com/aws/amazon-redshift-python-driver
// provides saml and IAM temp credential login

pub mod iam_provider;
pub mod saml_provider;

pub mod re {
    use regex::Regex;

    pub fn compile(pattern: &str) -> Regex {
        Regex::new(pattern).unwrap()
    }
}
