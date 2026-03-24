#![allow(clippy::result_large_err)]

use std::env;

use secrecy::SecretString;

use redshift_iam::prelude::*;

fn main() -> anyhow::Result<(), Box<dyn std::error::Error>> {
    // inputs:
    let host = env::var("HOST")?;
    let database = env::var("DATABASE")?;
    let query = "";

    let user = env::var("USER")?;
    let password = SecretString::new(env::var("PWD").unwrap().into_boxed_str());
    let cluster = env::var("CLUSTER")?;
    let autocreate = false;
    let preferred_role = env::var("ROLE_ARN")?;
    let idp_host = env::var("IDP_HOST")?;

    // Get aws_credentials from ping
    let ping_provider =
        PingCredentialsProvider::new(None::<String>, idp_host, None, user, password);
    let aws_credentials = ping_provider.get_credentials(preferred_role).unwrap();
    // or get them by any other means

    let (username, password) =
        IamProvider::new(ping_provider.user(), database.clone(), cluster, autocreate)
            // .set_region()
            .auth(aws_credentials);

    let conn = Redshift::new(username, password, host, None, database);

    let rbs = conn.execute(query)?;
    println!("{rbs:?}");

    Ok(())
}
