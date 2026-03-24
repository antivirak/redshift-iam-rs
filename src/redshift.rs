use arrow::record_batch::RecordBatch;
use connectorx::errors::ConnectorXOutError;
use secrecy::{ExposeSecret, SecretString};

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
