use std::env;

use base64::prelude::*;
use secrecy::SecretString;

use redshift_iam::prelude::*;
use redshift_iam::saml_provider::{SamlProvider, get_credentials};

// helpers

fn make_valid_ping_credentials_provider() -> PingCredentialsProvider {
    PingCredentialsProvider::new(
        None::<String>,
        "example.example.com",
        None,
        "user",
        SecretString::new("pwd".to_string().into_boxed_str()),
    )
}

// PingCredentialsProvider tests

#[test]
fn test_default_parameters_saml_credentials_provider() {
    let scp = make_valid_ping_credentials_provider();
    assert!(!scp.ssl_insecure);
    assert!(scp.do_verify_ssl_cert());
}

// get_credentials error-path tests
// mocks:

struct FailingSamlProvider;

impl SamlProvider for FailingSamlProvider {
    fn user(&self) -> String {
        "test_user".to_string()
    }

    async fn get_saml_assertion(&self) -> String {
        panic!("get_saml_assertion failed")
    }
}

/// When get_saml_assertion panics the panic must propagate out of
/// get_credentials unchanged.
#[tokio::test]
#[should_panic(expected = "get_saml_assertion failed")]
async fn test_get_saml_assertion_fails_propagates() {
    get_credentials(
        &FailingSamlProvider,
        "arn:aws:iam::123:role/test".to_string(),
    )
    .await;
}

struct NoRoleSamlProvider;

impl SamlProvider for NoRoleSamlProvider {
    fn user(&self) -> String {
        "test_user".to_string()
    }

    async fn get_saml_assertion(&self) -> String {
        // A valid base64-encoded XML document that contains no IAM role ARNs.
        BASE64_STANDARD.encode(b"<root></root>")
    }
}

#[tokio::test]
#[should_panic(expected = "No roles were found in SAML assertion")]
async fn test_refresh_saml_assertion_missing_role_should_fail() {
    get_credentials(
        &NoRoleSamlProvider,
        "arn:aws:iam::123:role/my-role".to_string(),
    )
    .await;
}

// Live integration test

/// End-to-end integration test requiring live credentials supplied via
/// environment variables. Skipped by default; run with:
///
///   HOST=... DATABASE=... USER=... PWD=... CLUSTER=... ROLE_ARN=... IDP_HOST=... \
///     cargo test test_live_connection -- --ignored
#[test]
#[ignore = "requires live credentials via environment variables"]
fn test_live_connection() {
    let host = env::var("HOST").expect("HOST env var required");
    let database = env::var("DATABASE").expect("DATABASE env var required");
    let query = "SELECT 1";
    let user = env::var("USER").expect("USER env var required");
    let password = SecretString::new(
        env::var("PWD")
            .expect("PWD env var required")
            .into_boxed_str(),
    );
    let cluster = env::var("CLUSTER").expect("CLUSTER env var required");
    let autocreate = false;
    let preferred_role = env::var("ROLE_ARN").expect("ROLE_ARN env var required");
    let idp_host = env::var("IDP_HOST").expect("IDP_HOST env var required");

    let ping_provider =
        PingCredentialsProvider::new(None::<String>, idp_host, None, user.clone(), password);
    let aws_credentials = ping_provider.get_credentials(preferred_role).unwrap();

    let (username, db_password) =
        IamProvider::new(user, database.clone(), cluster, autocreate).auth(aws_credentials);

    let conn = Redshift::new(username, db_password, host, None, database);
    let rbs = conn.execute(query).unwrap();
    assert!(!rbs.is_empty());
}
