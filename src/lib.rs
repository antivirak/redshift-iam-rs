// inspired by github.com/aws/amazon-redshift-python-driver
// provides saml and IAM temp credential login

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use std::borrow::Cow;
use std::collections::HashMap;

use arrow::record_batch::RecordBatch;
use aws_credential_types::provider::ProvideCredentials;
use aws_sdk_sts as sts;
use connectorx::errors::ConnectorXOutError;
use log::debug;
use secrecy::SecretString;
use tokio::runtime::Runtime;

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

/// Executes `query` against a Redshift cluster described by a JDBC-style IAM connection URI
/// and returns the results as Arrow [`RecordBatch`]es.
///
/// # URI format
///
/// ```text
/// [jdbc:]redshift:iam://<user>:<password>@<host>:<port>/<database>?<params>
/// ```
///
/// The `jdbc:` prefix is optional and stripped automatically. Supported query parameters
/// (all case-insensitive):
///
/// | Parameter | Description |
/// |---|---|
/// | `ClusterID` | Redshift cluster identifier (required for IAM auth) |
/// | `Region` | AWS region (default: `us-east-1`) |
/// | `AutoCreate` | `true` to auto-create the DB user |
/// | `IdP_Host` | PingFederate hostname. If absent, falls back to ambient AWS credentials |
/// | `IdP_Port` | PingFederate port (default: `443`) |
/// | `Preferred_Role` | IAM role ARN to assume via SAML |
/// | `Plugin_Name` | Ignored (reserved for Java driver compatibility) |
///
/// # Errors
///
/// Returns [`ConnectorXOutError::SourceNotSupport`] if the URI does not start with
/// `redshift:iam://`.
pub fn read_sql(
    query: &str,
    connection_uri: impl ToString,
) -> Result<Vec<RecordBatch>, ConnectorXOutError> {
    let uri_string = connection_uri.to_string();
    let mut uri_str = uri_string.trim();

    let (scheme, tail) = uri_str.split_once(":").unwrap();
    if scheme == "jdbc" {
        uri_str = tail;
    }
    let pattern = "redshift:iam://";
    if !uri_str.starts_with(pattern) {
        return Err(ConnectorXOutError::SourceNotSupport(format!(
            "The connection uri needs to start with {pattern}"
        )));
    }
    uri_str = uri_str.split_once("://").unwrap().1;
    let uri_str = format!("redshift://{uri_str}");
    let redshift_url = reqwest::Url::parse(&uri_str).unwrap();
    let database = redshift_url.path().trim_start_matches("/");

    let params: HashMap<String, Cow<str>> = HashMap::from_iter(
        redshift_url
            .query_pairs()
            .map(|(key, val)| (key.to_lowercase(), val)),
    );
    let autocreate = params
        .get("autocreate")
        .is_some_and(|val| val.to_lowercase() == "true");
    let cluster = params.get("clusterid").map_or("", |val| val);
    let idp_host = params.get("idp_host").map_or("", |val| val);
    let idp_port = params
        .get("idp_port")
        .and_then(|val| val.parse::<u16>().ok());
    let pwd = redshift_url.password().unwrap_or("");

    let aws_credentials = if idp_host.is_empty() || pwd.is_empty() {
        // No IdP credentials — fall back to ambient AWS credentials from the environment
        // TODO: other ways to log in from the uri parameters?
        debug!("Initiating IAM login");
        let rt = Runtime::new().unwrap();
        let creds = rt.block_on(async {
            aws_config::load_from_env()
                .await
                .credentials_provider()
                .unwrap()
                .provide_credentials()
                .await
                .unwrap()
        });
        sts::types::Credentials::builder()
            .set_access_key_id(Some(creds.access_key_id().to_string()))
            .set_secret_access_key(Some(creds.secret_access_key().to_string()))
            .set_session_token(creds.session_token().map(str::to_string))
            .build()
            .unwrap()
    } else {
        let plugin_string = params.get("plugin_name").map_or(String::new(), |val| val.to_lowercase());
        let plugin = plugin_string.trim_start_matches("com.amazon.redshift.plugin.");
        let plugin_expected = "pingcredentialsprovider";
        if !plugin.is_empty() && plugin != plugin_expected {
            panic!("Expected {plugin_expected}; feel free to contribute other provider implementation");
        }
        let ping_provider = PingCredentialsProvider::new(
            None::<String>,
            idp_host,
            idp_port,
            redshift_url.username(),
            SecretString::new(pwd.to_string().into_boxed_str()),
        );
        // TODO: validate arn format?
        ping_provider
            .get_credentials(params.get("preferred_role").map_or("", |val| val))
            .unwrap()
    };

    let mut iam_provider = IamProvider::new(redshift_url.username(), database, cluster, autocreate);
    if let Some(region) = params.get("region") {
        iam_provider = iam_provider.set_region(region);
    }
    let (username, password) = iam_provider.auth(aws_credentials);

    Redshift::new(
        username,
        password,
        redshift_url.host_str().unwrap(),
        redshift_url.port(),
        database,
    )
    .execute(query)
}
