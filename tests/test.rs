use std::env;

use base64::prelude::*;
use secrecy::{ExposeSecret, SecretString};

use redshift_iam::prelude::*;
use redshift_iam::saml_provider::{SamlProvider, get_credentials, parse_saml_assertion};

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

#[test]
fn test_ping_ssl_insecure_disables_verify() {
    let mut scp = make_valid_ping_credentials_provider();
    scp.ssl_insecure = true;
    assert!(!scp.do_verify_ssl_cert());
}

#[test]
fn test_ping_user_getter() {
    let scp = make_valid_ping_credentials_provider();
    assert_eq!(scp.user(), "user");
}

// PingCredentialsProvider happy path

const SAML_RESPONSE_HTML: &str = r#"<html><body>
<form method="POST" action="https://signin.aws.amazon.com/saml">
  <INPUT type="hidden" name="SAMLResponse" value="dGVzdA==" />
</form>
</body></html>"#;

// parse_saml_assertion tests

#[test]
fn test_parse_saml_assertion_extracts_value() {
    assert_eq!(parse_saml_assertion(SAML_RESPONSE_HTML), "dGVzdA==");
}

#[test]
#[should_panic(expected = "Failed to retrieve SAMLAssertion")]
fn test_parse_saml_assertion_missing_panics() {
    parse_saml_assertion("<html><body><form></form></body></html>");
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

// Sync path for PingCredentialsProvider::get_credentials

#[test]
#[should_panic(expected = "reqwest::Error")]
fn test_sync_get_saml_assertion_fails_propagates() {
    let scp = make_valid_ping_credentials_provider();
    scp.get_credentials("arn:aws:iam::123:role/test".to_string());
}

// IamProvider tests

#[test]
fn test_iam_provider_default_region() {
    let iam = IamProvider::new("user", "db", "cluster", false);
    assert_eq!(iam.region(), "us-east-1");
}

#[test]
fn test_iam_provider_set_region_overrides_default() {
    let iam = IamProvider::new("user", "db", "cluster", true).set_region("ap-southeast-1");
    assert_ne!(iam.region(), "us-east-1");
    assert_eq!(iam.region(), "ap-southeast-1");
}

// Redshift tests

#[test]
fn test_redshift_connection_string_postgresql_scheme() {
    let r = Redshift::new("user", "pass", "host", None, "db");
    assert!(
        r.connection_string()
            .expose_secret()
            .starts_with("postgresql://")
    );
}

#[test]
fn test_redshift_connection_string_default_port() {
    let r = Redshift::new("user", "pass", "my-host", None, "mydb");
    assert!(r.connection_string().expose_secret().contains(":5439/"));
}

#[test]
fn test_redshift_connection_string_custom_port() {
    let r = Redshift::new("user", "pass", "my-host", Some(5440), "mydb");
    let cs = r.connection_string();
    assert!(cs.expose_secret().contains(":5440/"));
    assert!(!cs.expose_secret().contains(":5439/"));
}

#[test]
fn test_redshift_connection_string_contains_host_and_database() {
    let r = Redshift::new("user", "pass", "my-host.example.com", None, "analytics");
    let cs = r.connection_string();
    assert!(cs.expose_secret().contains("my-host.example.com"));
    assert!(cs.expose_secret().contains("/analytics"));
}

#[test]
fn test_redshift_connection_string_url_encodes_credentials() {
    // '@' in a password must be percent-encoded so the URL remains valid
    let r = Redshift::new("user", "p@ssword", "host", None, "db");
    let cs = r.connection_string();
    assert!(!cs.expose_secret().contains(":p@ssword@"));
    assert!(cs.expose_secret().contains("p%40ssword"));
}

#[test]
fn test_redshift_connection_string_includes_cxprotocol() {
    let r = Redshift::new("user", "pass", "host", None, "db");
    assert!(
        r.connection_string()
            .expose_secret()
            .contains("cxprotocol=cursor")
    );
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
        PingCredentialsProvider::new(None::<String>, idp_host, None, user.as_str(), password);
    let aws_credentials = ping_provider.get_credentials(preferred_role).unwrap();

    let (username, db_password) =
        IamProvider::new(user, database.clone(), cluster, autocreate).auth(aws_credentials);

    let conn = Redshift::new(username, db_password, host, None, database);
    let rbs = conn.execute(query).unwrap();
    assert!(!rbs.is_empty());
}
