use aws_credential_types::Credentials;
use aws_sdk_redshift as redshift;
use aws_sdk_sts as sts;
// use secrecy::SecretString;
use tokio::runtime::Runtime;

use crate::saml_provider::PingCredentialsProvider;

pub struct IamProvider {
    provider: PingCredentialsProvider, // TODO generic
    database: String,
    cluster: String,
    autocreate: bool,
}

impl IamProvider {
    pub fn new(
        provider: PingCredentialsProvider,
        database: String,
        cluster: String,
        autocreate: bool,
    ) -> IamProvider {
        IamProvider {
            provider,
            database,
            cluster,
            autocreate,
        }
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
                .region(Some(redshift::config::Region::new("us-east-1"))) // default
                .build();
            let client = redshift::Client::from_conf(config);
            let cluster_creds = client
                .get_cluster_credentials()
                .set_db_user(Some(self.provider.user()))
                .set_db_name(Some(self.database.clone()))
                .set_cluster_identifier(Some(self.cluster.clone()))
                .set_duration_seconds(Some(3600))
                .set_auto_create(Some(self.autocreate))
                .send()
                .await
                .unwrap(); //?

            let user = cluster_creds.db_user.unwrap();
            let password = cluster_creds.db_password.unwrap();
            (user, password)
        })
    }
}
