# redshift-iam

A Rust library for authenticating to Amazon Redshift using SAML-based single sign-on (SSO) or IAM temporary credentials. Inspired by the [Amazon Redshift Python driver](https://github.com/aws/amazon-redshift-python-driver).

## Overview

The authentication flow has three stages:

1. **SAML assertion** — `PingCredentialsProvider` logs in to a PingFederate IdP and retrieves a SAML assertion. This step is optional.
2. **IAM credentials** — The assertion is exchanged for temporary AWS credentials via STS `AssumeRoleWithSAML`.
3. **Redshift credentials** — The temporary AWS credentials are used to call `GetClusterCredentials`, obtaining a short-lived Redshift username/password.
4. **Query** — `Redshift` connects using those credentials and executes queries, returning Arrow `RecordBatch`es.

The query execution is only enabled if you include read_sql feature. Otherwise, you can get the connection_string and execute queries via other crates.

## Usage

```rust,no_run
use std::collections::HashMap;
use secrecy::SecretString;
use redshift_iam::prelude::*;

let password = SecretString::new("my-password".to_string().into_boxed_str());

// 1. Obtain a SAML assertion from PingFederate and exchange it for AWS credentials
let ping_provider = PingCredentialsProvider::new(
    &HashMap::new(),         // optionally containing partnerspid key (empty map = default "urn:amazon:webservices")
    "pingfed.example.com",   // IdP host
    None,                    // IdP port (None = 443)
    "alice@example.com",     // username
    password,
);
let aws_credentials = ping_provider
    .get_credentials("arn:aws:iam::123456789012:role/RedshiftRole")
    .unwrap();

// 2. Exchange AWS credentials for Redshift cluster credentials
let (username, db_password) = IamProvider::new(
    "alice",                 // DB user
    "analytics",             // database
    "my-cluster",            // cluster identifier
    false,                   // auto-create user
)
// .set_region("eu-west-1") // optional, default: us-east-1
.auth(aws_credentials);

// 3. Connect and query
let conn = Redshift::new(username, db_password, "my-cluster.example.com", None, "analytics");
#[cfg(feature = "read_sql")]
let batches = conn.execute("SELECT * FROM my_table LIMIT 10").unwrap();
```

## API

### `PingCredentialsProvider`

Authenticates against a PingFederate IdP and retrieves temporary AWS credentials via SAML.

```rust,ignore
PingCredentialsProvider::new(
    partner_sp_id: &HashMap::new(),  // empty map -> "urn%3Aamazon%3Awebservices"
    idp_host: impl ToString,
    idp_port: Option<u16>,                 // None -> 443
    user_name: impl ToString,
    password: SecretString,
) -> Self
```

| Method | Description |
|---|---|
| `get_credentials(role_arn)` | Full sync flow: SAML -> STS -> returns `sts::types::Credentials` |
| `user()` | Returns the configured username |
| `do_verify_ssl_cert()` | Returns `true` unless `ssl_insecure` is set |
| `ssl_insecure: bool` (pub field) | Set to `true` to skip TLS verification |

### `IamProvider`

Exchanges temporary AWS credentials for Redshift cluster credentials.

```rust,ignore
IamProvider::new(user, database, cluster, autocreate) -> Self
```

| Method | Description |
|---|---|
| `auth(aws_credentials)` | Calls `GetClusterCredentials`, returns `(username, password)` |
| `set_region(region)` | Builder method to set the AWS region (default: `us-east-1`) |
| `region()` | Returns the configured region |

### `Redshift`

Executes SQL queries against a Redshift cluster, returning Arrow `RecordBatch`es.

```rust,ignore
Redshift::new(username, password, host, port: Option<u16>, database) -> Self
```

| Method | Description |
|---|---|
| `execute(query)` | Runs the query and returns `Vec<RecordBatch>` |
| `connection_string()` | Returns the URL-encoded connection string as a `SecretString` |

Port defaults to `5439` if `None` is passed.

### Custom SAML providers

You are not limited to PingFederate. Any type that implements the `SamlProvider` trait can be
passed directly to the async `get_credentials` free function:

```rust,ignore
use redshift_iam::{SamlProvider, get_credentials};

struct MyIdpProvider { /* ... */ }

impl SamlProvider for MyIdpProvider {
    async fn get_saml_assertion(&self) -> String {
        // call your own IdP and return the base64-encoded SAMLResponse value
        todo!()
    }
}

let aws_credentials = get_credentials(
    &MyIdpProvider { /* ... */ },
    "arn:aws:iam::123456789012:role/RedshiftRole".to_string(),
)
.await
.unwrap();
```

The `SamlProvider` trait requires:

| Item | Description |
|---|---|
| `async fn get_saml_assertion(&self) -> String` | Returns the base64-encoded SAML assertion |

The live integration test (`cargo test test_live_connection -- --ignored`) reads credentials from the environment:

| Variable | Description |
|---|---|
| `IDP_HOST` | PingFederate hostname |
| `USER` | Redshift / IdP username |
| `PWD` | Password |
| `ROLE_ARN` | IAM role ARN to assume |
| `CLUSTER` | Redshift cluster identifier |
| `HOST` | Redshift cluster hostname |
| `DATABASE` | Database name |

## Running tests

```sh
# Unit and mock-based tests only
cargo test

# Include the live integration test (requires env vars above)
HOST=... DATABASE=... USER=... PWD=... CLUSTER=... ROLE_ARN=... IDP_HOST=... \
  cargo test test_live_connection -- --ignored
```
