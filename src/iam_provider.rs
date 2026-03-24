use aws_credential_types::Credentials;
use aws_sdk_redshift as redshift;
use aws_sdk_sts as sts;
use tokio::runtime::Runtime;

pub struct IamProvider {
    user: String,
    database: String,
    cluster: String,
    autocreate: bool,
    region: String,
}

impl IamProvider {
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

    pub fn set_region(mut self, region: impl ToString) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn region(&self) -> String {
        self.region.clone()
    }

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
                .set_duration_seconds(Some(3600))
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
