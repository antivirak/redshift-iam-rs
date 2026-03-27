// inspired by github.com/aws/amazon-redshift-python-driver
// provides saml and IAM temp credential login

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use arrow::record_batch::RecordBatch;
use aws_credential_types::provider::ProvideCredentials;
use aws_sdk_sts as sts;
use connectorx::errors::ConnectorXOutError;
use log::{debug, error};
use secrecy::{ExposeSecret, SecretString};
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

/// Identifies the SAML provider plugin to use when an IdP host is present in the
/// connection URI.
///
/// The `Plugin_Name` query parameter in the JDBC URI is parsed into one of these
/// variants. The optional `com.amazon.redshift.plugin.` prefix is stripped
/// automatically, so both `"PingCredentialsProvider"` and
/// `"com.amazon.redshift.plugin.PingCredentialsProvider"` resolve to
/// [`PluginName::PingCredentialsProvider`].
///
/// Only [`PluginName::PingCredentialsProvider`] has a built-in factory.
/// All other variants require a factory to be registered via [`register_provider`]
/// before calling [`read_sql`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginName {
    /// PingFederate IdP (built-in — backed by [`PingCredentialsProvider`]).
    PingCredentialsProvider,
    /// Okta IdP.
    OktaCredentialsProvider,
    /// Browser-based SAML flow.
    BrowserSamlCredentialsProvider,
    /// Browser-based Azure AD SAML flow.
    BrowserAzureCredentialsProvider,
    /// Azure AD IdP.
    AzureCredentialsProvider,
    /// ADFS IdP.
    AdfsCredentialsProvider,
    /// User-defined custom provider.
    CustomCredentialsProvider,
    /// Fallback for unrecognised `Plugin_Name` values.
    UnknownCredentialsProvider,
}

impl From<&str> for PluginName {
    /// Converts a `Plugin_Name` URI parameter value to a `PluginName` variant.
    ///
    /// The optional `com.amazon.redshift.plugin.` package prefix is stripped
    /// before matching. Comparison is case-insensitive. Unrecognised strings
    /// map to [`PluginName::UnknownCredentialsProvider`].
    fn from(s: &str) -> Self {
        let name = s
            .trim()
            .trim_start_matches("com.amazon.redshift.plugin.")
            .to_lowercase();
        match name.as_str() {
            "pingcredentialsprovider" => Self::PingCredentialsProvider,
            "oktacredentialsprovider" => Self::OktaCredentialsProvider,
            "browsersamlcredentialsprovider" => Self::BrowserSamlCredentialsProvider,
            "browserazurecredentialsprovider" => Self::BrowserAzureCredentialsProvider,
            "azurecredentialsprovider" => Self::AzureCredentialsProvider,
            "adfscredentialsprovider" => Self::AdfsCredentialsProvider,
            "customcredentialsprovider" => Self::CustomCredentialsProvider,
            _ => Self::UnknownCredentialsProvider,
        }
    }
}

/// Type-erased factory function stored in the provider registry.
type ProviderFactory = Arc<
    dyn Fn(
            &HashMap<String, Cow<str>>,
            &str,
            Option<u16>,
            &str,
            SecretString,
        ) -> Box<dyn SamlProvider>
        + Send
        + Sync,
>;

static PROVIDER_REGISTRY: OnceLock<Mutex<HashMap<PluginName, ProviderFactory>>> = OnceLock::new();

/// Returns the global provider registry, pre-populated with the built-in
/// [`PluginName::PingCredentialsProvider`] -> [`PingCredentialsProvider`] mapping.
fn registry() -> &'static Mutex<HashMap<PluginName, ProviderFactory>> {
    PROVIDER_REGISTRY.get_or_init(|| {
        let mut map: HashMap<PluginName, ProviderFactory> = HashMap::new();
        map.insert(
            PluginName::PingCredentialsProvider,
            Arc::new(|conn_params, host, port, user, pwd| {
                Box::new(PingCredentialsProvider::new(
                    conn_params,
                    host,
                    port,
                    user,
                    pwd,
                ))
            }),
        );
        Mutex::new(map)
    })
}

/// Registers a factory for the given [`PluginName`] variant.
///
/// The factory receives `(conn_parameters, idp_host, idp_port, username, password)` and must
/// return a `Box<dyn SamlProvider>`. Call this once at application startup
/// before invoking [`read_sql`].
///
/// conn_parameters is a map of provider-specific arguments, like PartnerSpId for Ping,
/// app_id - Used only with Okta. https://example.okta.com/home/amazon_aws/0oa2hylwrpM8UGehd1t7/272
/// idp_tenant - A tenant used for Azure AD. Used only with Azure.
/// client_id - A client ID for the Amazon Redshift enterprise application in Azure AD. Used only with Azure.
///
/// [`PluginName::PingCredentialsProvider`] is pre-registered and maps to
/// [`PingCredentialsProvider`]. Registering it again replaces the built-in.
///
/// # Example
///
/// ```rust,no_run
/// use secrecy::SecretString;
/// use redshift_iam::{register_provider, PluginName, SamlProvider};
///
/// struct MyOktaProvider;
///
/// #[async_trait::async_trait]
/// impl SamlProvider for MyOktaProvider {
///     async fn get_saml_assertion(&self) -> String { todo!() }
/// }
///
/// register_provider(PluginName::OktaCredentialsProvider, |_conn_params, _host, _port, _user, _pwd| {
///     Box::new(MyOktaProvider)
/// });
/// ```
pub fn register_provider(
    plugin: PluginName,
    factory: impl Fn(
        &HashMap<String, Cow<str>>,
        &str,
        Option<u16>,
        &str,
        SecretString,
    ) -> Box<dyn SamlProvider>
    + Send
    + Sync
    + 'static,
) {
    registry().lock().unwrap().insert(plugin, Arc::new(factory));
}

fn get_redshift_from_uri(connection_uri: impl ToString) -> Result<Redshift, ConnectorXOutError> {
    let uri_string = connection_uri.to_string();
    let mut uri_str = uri_string.trim();

    let pattern = "redshift:iam://";
    let (scheme, tail) = match uri_str.split_once(':') {
        Some((scheme, tail)) => (scheme, tail),
        None => {
            return Err(ConnectorXOutError::SourceNotSupport(format!(
                "The connection uri needs to start with {pattern}"
            )));
        }
    };
    if scheme == "jdbc" {
        uri_str = tail;
    }
    if !uri_str.starts_with(pattern) && !uri_str.starts_with("redshift-iam://") {
        return Err(ConnectorXOutError::SourceNotSupport(format!(
            "The connection uri needs to start with {pattern}"
        )));
    }
    uri_str = uri_str.split_once("://").unwrap().1;
    let uri_str = format!("redshift://{uri_str}");
    let redshift_url = reqwest::Url::parse(&uri_str).map_err(|e| {
        ConnectorXOutError::SourceNotSupport(format!("Invalid Redshift IAM URI: {e}"))
    })?;
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
        let plugin_name = PluginName::from(params.get("plugin_name").map_or("", |v| v.as_ref()));
        let factory = registry()
            .lock()
            .unwrap()
            .get(&plugin_name)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "No SAML provider registered for {plugin_name:?}. \
                    Register one with register_provider() before calling read_sql."
                )
            });
        let provider = factory(
            &params,
            idp_host,
            idp_port,
            redshift_url.username(),
            SecretString::new(pwd.to_string().into_boxed_str()),
        );
        aws_creds_from_saml(provider, params.get("preferred_role").map_or("", |val| val))
    };

    let mut iam_provider = IamProvider::new(redshift_url.username(), database, cluster, autocreate);
    if let Some(region) = params.get("region") {
        iam_provider = iam_provider.set_region(region);
    }
    let (username, password) = iam_provider.auth(aws_credentials);

    Ok(Redshift::new(
        username,
        password,
        redshift_url.host_str().unwrap(),
        redshift_url.port(),
        database,
    ))
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
/// | `IdP_Host` | IdP hostname. If absent, falls back to ambient AWS credentials |
/// | `IdP_Port` | IdP port (default: `443`) |
/// | `Plugin_Name` | SAML provider variant (e.g. `PingCredentialsProvider`). Maps to [`PluginName`]. |
/// | `Preferred_Role` | IAM role ARN to assume via SAML |
///
/// When `IdP_Host` and a password are present the `Plugin_Name` parameter is
/// parsed into a [`PluginName`] variant and looked up in the global registry.
/// [`PluginName::PingCredentialsProvider`] is pre-registered. All other variants
/// must be registered first via [`register_provider`].
///
/// # Errors
///
/// Returns [`ConnectorXOutError::SourceNotSupport`] if the URI does not start with
/// `redshift:iam://`.
pub fn read_sql(
    query: &str,
    connection_uri: impl ToString,
) -> Result<Vec<RecordBatch>, ConnectorXOutError> {
    let redshift = get_redshift_from_uri(connection_uri).unwrap();
    redshift.execute(query)
}

/// Converts a Redshift IAM connection URI into a parsed PostgreSQL connection string
/// with temporary credentials already embedded.
///
/// Parses `connection_uri`, performs the full IAM / SAML authentication flow (identical
/// to [`read_sql`]), and returns the resulting `postgres://` URL with the short-lived
/// username and password substituted in.
///
/// This is useful when you need to hand a live connection string to a third-party
/// library that speaks the PostgreSQL wire protocol directly (e.g. `sqlx`, `diesel`,
/// `psycopg2` via a subprocess) without going through `connectorx`.
///
/// # URI format
///
/// Accepts the same `[jdbc:]redshift:iam://…` format described in [`read_sql`].
///
/// # Fallback behaviour
///
/// If the IAM / SAML exchange fails, the error is logged at the `error` level and the
/// function falls back to returning the original URI with its scheme replaced by
/// `postgres`. This allows callers to still attempt a direct connection using
/// whatever credentials were present in the URI.
///
/// # Returns
///
/// A `postgres://username:password@host:port/database` connection string as an
/// Url instance. The password is a short-lived STS session token and should
/// not be cached beyond its expiry window.
pub fn redshift_to_postgres(connection_uri: impl ToString) -> reqwest::Url {
    let redshift_res = get_redshift_from_uri(connection_uri.to_string());
    if let Ok(redshift) = redshift_res {
        // already parsed before, safe to unwrap
        reqwest::Url::parse(redshift.connection_string().expose_secret()).unwrap()
    } else {
        error!(
            "Logging to redshift using redshift-iam crate failed with: {:?}",
            redshift_res.err()
        );
        let mut uri = reqwest::Url::parse(&connection_uri.to_string()).unwrap(); // we need to return Url; if not parsable, just panic
        uri.set_scheme("postgres").unwrap(); // postgres is valid scheme, no reason for panic
        uri
    }
}

/// Obtains temporary AWS credentials from any [`SamlProvider`] synchronously.
///
/// Drives the async [`saml_provider::get_credentials`] on a new Tokio runtime.
fn aws_creds_from_saml(
    provider: Box<dyn SamlProvider>,
    preferred_role: &str,
) -> sts::types::Credentials {
    let rt = Runtime::new().unwrap();
    rt.block_on(crate::saml_provider::get_credentials(
        provider.as_ref(),
        preferred_role.to_string(),
    ))
    .unwrap()
}
