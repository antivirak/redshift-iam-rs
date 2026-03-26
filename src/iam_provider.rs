use aws_credential_types::Credentials;
use aws_sdk_redshift as redshift;
use aws_sdk_sts as sts;
use tokio::runtime::Runtime;

/// Exchanges temporary AWS credentials for short-lived Redshift cluster credentials
/// via `redshift:GetClusterCredentials`.
#[derive(Debug)]
pub struct IamProvider {
    user: String,
    database: String,
    cluster: String,
    autocreate: bool,
    region: String,
}

impl IamProvider {
    /// Creates a new `IamProvider`.
    ///
    /// - `autocreate`: When `true`, the Redshift user is created automatically if it
    ///   does not already exist.
    /// - The AWS region defaults to `"us-east-1"`; change it with [`set_region`](Self::set_region).
    ///
    /// # Examples
    /// ```
    /// use redshift_iam::IamProvider;
    /// let iam = IamProvider::new("alice", "analytics", "my-cluster", false);
    /// assert_eq!(iam.region(), "us-east-1");
    /// ```
    pub fn new(
        user: impl ToString,
        database: impl ToString,
        cluster: impl ToString,
        autocreate: bool,
    ) -> Self {
        Self {
            user: user.to_string(),
            database: database.to_string(),
            cluster: cluster.to_string(),
            autocreate,
            region: "us-east-1".to_string(),
        }
    }

    fn user(&self) -> String {
        self.user.clone()
    }

    /// Overrides the AWS region used when calling `GetClusterCredentials`.
    ///
    /// # Examples
    /// ```
    /// use redshift_iam::IamProvider;
    /// let iam = IamProvider::new("alice", "analytics", "my-cluster", false)
    ///     .set_region("eu-west-1");
    /// assert_eq!(iam.region(), "eu-west-1");
    /// ```
    pub fn set_region(mut self, region: impl ToString) -> Self {
        self.region = region.to_string();
        self
    }

    /// Returns the configured AWS region.
    pub fn region(&self) -> String {
        self.region.clone()
    }

    /// Calls `redshift:GetClusterCredentials` with the provided AWS credentials and
    /// returns a `(username, password)` pair valid for 3600 seconds.
    pub fn auth(&self, aws_credentials: sts::types::Credentials) -> (String, String) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let creds = Credentials::from_keys(
                aws_credentials.access_key_id().to_string(),
                aws_credentials.secret_access_key().to_string(),
                Some(aws_credentials.session_token().to_string()),
            );
            let config = redshift::Config::builder()
                .credentials_provider(creds)
                .region(Some(redshift::config::Region::new(self.region())))
                .build();
            let client = redshift::Client::from_conf(config);
            let cluster_creds = client
                .get_cluster_credentials()
                .set_db_user(Some(self.user()))
                .set_db_name(Some(self.database.clone()))
                .set_cluster_identifier(Some(self.cluster.clone()))
                .set_duration_seconds(Some(3600)) // can be 900-3600
                .set_auto_create(Some(self.autocreate))
                .send()
                .await
                .unwrap(); //?

            (
                cluster_creds.db_user.unwrap(),
                cluster_creds.db_password.unwrap(),
            )
        })
    }
}
