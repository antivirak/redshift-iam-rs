#[cfg(feature = "read_sql")]
use arrow::record_batch::RecordBatch;
#[cfg(feature = "read_sql")]
use connectorx::errors::ConnectorXOutError;
#[cfg(feature = "read_sql")]
use secrecy::ExposeSecret;
use secrecy::SecretString;

/// Client for executing queries against an Amazon Redshift cluster.
///
/// Uses [ConnectorX](https://github.com/sfu-db/connector-x) under the hood and
/// returns results as Arrow [`RecordBatch`]es.
pub struct Redshift {
    username: String,
    password: String,
    host: String,
    port: Option<u16>,
    database: String,
    connection_string: Option<SecretString>,
    // require_ssl: bool,
}

impl Redshift {
    /// Creates a new `Redshift` client.
    ///
    /// `port` defaults to `5439` when `None`.
    ///
    /// # Examples
    /// ```
    /// use redshift_iam::Redshift;
    /// use secrecy::ExposeSecret;
    ///
    /// let r = Redshift::new("alice", "s3cr3t", "my-host.example.com", None, "analytics");
    /// let cs = r.connection_string();
    /// assert!(cs.expose_secret().starts_with("postgresql://"));
    /// assert!(cs.expose_secret().contains(":5439/"));
    /// assert!(cs.expose_secret().contains("my-host.example.com"));
    /// assert!(cs.expose_secret().contains("/analytics"));
    /// ```
    pub fn new(
        username: impl ToString,
        password: impl ToString,
        host: impl ToString,
        port: Option<u16>,
        database: impl ToString,
    ) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            host: host.to_string(),
            port,
            database: database.to_string(),
            connection_string: None::<SecretString>,
            // require_ssl: bool,
        }
    }

    /// Builds the URL-encoded `postgresql://` connection string used by ConnectorX.
    ///
    /// Credentials are percent-encoded so that special characters (e.g. `@`) do not
    /// corrupt the URL. The result is wrapped in a [`SecretString`] to prevent
    /// accidental logging.
    ///
    /// # Examples
    /// ```
    /// use redshift_iam::Redshift;
    /// use secrecy::ExposeSecret;
    ///
    /// // Special characters in passwords are percent-encoded
    /// let r = Redshift::new("user", "p@ssword", "host", None, "db");
    /// let cs = r.connection_string();
    /// assert!(cs.expose_secret().contains("p%40ssword"));
    /// assert!(cs.expose_secret().contains("cxprotocol=cursor"));
    /// ```
    pub fn connection_string(&self) -> SecretString {
        if let Some(connection_string) = &self.connection_string {
            return connection_string.clone();
        }
        let uri = format!(
            "postgresql://{}:{}/{}?cxprotocol=cursor",
            self.host,
            self.port.unwrap_or(5439),
            self.database,
        );
        let mut redshift_url = reqwest::Url::parse(&uri).unwrap();
        // URL-encode credentials
        redshift_url.set_username(&self.username).unwrap();
        redshift_url.set_password(Some(&self.password)).unwrap();

        SecretString::new(redshift_url.as_str().to_string().into_boxed_str())
    }

    /// Executes `query` and returns the results as a `Vec<RecordBatch>`.
    #[cfg(feature = "read_sql")]
    pub fn execute(&self, query: impl ToString) -> Result<Vec<RecordBatch>, ConnectorXOutError> {
        // could make more flexible by letting user specify output format
        let destination = connectorx::get_arrow::get_arrow(
            &connectorx::source_router::SourceConn::try_from(
                self.connection_string().expose_secret(),
            )
            .unwrap(),
            None,
            &[connectorx::sql::CXQuery::Naked(query.to_string())],
            None,
        )?;
        Ok(destination.arrow()?)
    }
}
