#![allow(clippy::result_large_err)]

use std::env;

// use aws_config;
// use connectorx;
use tokio::runtime::Runtime;
// use reqwest;
use secrecy::SecretString;

use redshift_iam::iam_provider::IamProvider;
use redshift_iam::saml_provider::{PingCredentialsProvider, get_credentials};

fn main() -> anyhow::Result<(), Box<dyn std::error::Error>> {
    // TODO: Rc<char> instead of String?
    // inputs:
    let host = env::var("HOST")?;
    let port = env::var("PORT")?; // could be default
    let database = env::var("DATABASE")?;
    let query = "".to_string();

    // inputs only used in async scope:
    let user = env::var("USER").unwrap().to_string();
    let password = SecretString::new(env::var("PWD").unwrap().into_boxed_str());
    let cluster = env::var("CLUSTER").unwrap().to_string();
    let autocreate = false;
    let preferred_role = env::var("ROLE_ARN").unwrap().to_string();
    let idp_host = env::var("IDP_HOST").unwrap();

    let ping_provider = PingCredentialsProvider::new(idp_host, 443, user, password);

    let rt = Runtime::new()?;
    let aws_credentials = rt.block_on(async {
        get_credentials(&ping_provider, preferred_role)
            .await
            .unwrap()
    });

    let (username, password) =
        IamProvider::new(ping_provider, database.clone(), cluster, autocreate)
            .auth(aws_credentials);

    let uri = format!("postgresql://{host}:{port}/{database}?cxprotocol=cursor");
    let mut redshift_url = reqwest::Url::parse(&uri).unwrap();
    // URL-encode credentials
    redshift_url.set_username(&username).unwrap();
    redshift_url.set_password(Some(&password)).unwrap();

    // could make more flexible by letting user specify output format
    let destination = connectorx::get_arrow::get_arrow(
        &connectorx::source_router::SourceConn::try_from(redshift_url.as_str()).unwrap(),
        None,
        &[connectorx::sql::CXQuery::Naked(query)],
        None,
    )?;
    let rbs = destination.arrow()?;
    println!("{rbs:?}");

    Ok(())
}
