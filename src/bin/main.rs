// inspired by github.com/aws/amazon-redshift-python-driver
// provides saml and IAM temp credential login

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::env;
use std::str;

// use aws_config;
use aws_credential_types::Credentials;
use aws_sdk_redshift as redshift;
use aws_sdk_sts as sts;
use base64::prelude::*;
// use connectorx;
use log::debug;
use tokio::runtime::Runtime;
// use reqwest;
use scraper::{ElementRef, Html, Selector};
use secrecy::{ExposeSecret, SecretString};

mod re {
    use regex::Regex;

    pub fn compile(pattern: &str) -> Regex {
        Regex::new(pattern).unwrap()
    }
}

fn is_password(inputtag: &ElementRef) -> bool {
    inputtag.attr("type") == Some("password")
}

fn is_text(inputtag: &ElementRef) -> bool {
    inputtag.attr("type") == Some("text")
}

fn get_form_action(soup: &Html) -> Option<&str> {
    // NOTE: selector case-insensitive; it will match both form and FORM
    let selector = Selector::parse("form").unwrap();

    for inputtag in soup.select(&selector) {
        let action = inputtag.attr("action");
        if action.is_some() {
            let method = inputtag.attr("form method");
            if method.is_some() && method.unwrap().to_uppercase() != "POST" {
                // safe unwrap
                println!("Warning: found action, but method is not POST. Skipping.");
                continue;
            }
            return action;
        }
    }

    None
}

pub struct PingCredentialsProvider {
    pub partner_sp_id: String, // pub, so anyone can change it without setter
    idp_host: String,
    idp_port: u16,
    user_name: String,
    password: SecretString,
    ssl_insecure: bool,
}

// TODO: move structs to lib and in main leave only tests
// TODO: Rc<char> instead of String?
///Identity Provider Plugin providing single sign-on access to an Amazon Redshift cluster using PingOne.
impl PingCredentialsProvider {
    // See Amazon Redshift docs
    // <https://docs.aws.amazon.com/redshift/latest/mgmt/options-for-providing-iam-credentials.html>_
    // for setup instructions.

    pub fn new(
        idp_host: impl ToString,
        idp_port: u16,
        user_name: impl ToString,
        password: SecretString,
        // TODO: kwargs either as builder or as Option<>. For now I hardcode them.
    ) -> PingCredentialsProvider {
        // We could either accept pwd and create secretString here or force user to pass it
        PingCredentialsProvider {
            partner_sp_id: "urn%3Aamazon%3Awebservices".to_string(),
            idp_host: idp_host.to_string(),
            idp_port, // could be 443 by default
            user_name: user_name.to_string(),
            password,
            ssl_insecure: false,
        }
    }

    // @property
    fn do_verify_ssl_cert(&self) -> bool {
        !self.ssl_insecure
    }

    ///Get SAML assertion.
    pub async fn get_saml_assertion(&self) -> String {
        // Method to grab the SAML Response. Used to refresh temporary credentials.
        debug!("PingCredentialsProvider.get_saml_assertion");
        let session = reqwest::Client::builder() // scoped only in this method
            .cookie_store(true) // the PF=... session state cookie needs to be preserved
            // .https_only(true)
            .build()
            .unwrap();

        let mut url = format!(
            "https://{}:{}/idp/startSSO.ping?PartnerSpId={}",
            self.idp_host, self.idp_port, self.partner_sp_id,
        );

        debug!(
            "Issuing GET request for Ping IdP login page using uri={} verify={}",
            url,
            self.do_verify_ssl_cert(),
        );
        let resp = session.get(&url).send().await.unwrap(); // TODO: , verify=self.do_verify_ssl_cert()
        debug!("Response code: {}", resp.status());
        debug!("response length: {}", resp.content_length().unwrap());

        let resp_text = &resp.text().await.unwrap();
        let soup = Html::parse_document(resp_text);

        let mut payload: HashMap<&str, &str> = HashMap::new();
        let mut username_found = false;
        let mut pwd_found = false;

        debug!(
            "Looking for username and password input tags in Ping IdP login page in order to build authentication request payload"
        );
        let selector = Selector::parse("INPUT").unwrap();
        for inputtag in soup.select(&selector) {
            let name = inputtag.attr("name").unwrap_or("");
            let id_ = inputtag.attr("id").unwrap_or("");
            debug!("name={name} , id={id_}");

            if !username_found && is_text(&inputtag) && id_ == "username" {
                debug!("Using tag with name {name} for username");
                payload.insert(name, &self.user_name);
                username_found = true;
            } else if is_password(&inputtag) && name.contains("pass") {
                debug!("Using tag with name {name} for password");
                if pwd_found {
                    let exec_msg = "Failed to parse Ping IdP login form. More than one password field was found on the Ping IdP login page";
                    panic!("{exec_msg}"); // We cannot do much about it, just panic
                }
                payload.insert(name, self.password.expose_secret());
                pwd_found = true;
            } else if !name.is_empty() {
                let value = inputtag.attr("value").unwrap_or("");
                payload.insert(name, value);
            }
        }

        if !username_found {
            debug!(
                "username tag still not found, continuing search using secondary preferred tags"
            );
            for inputtag in soup.select(&selector) {
                let name = inputtag.attr("name").unwrap_or("");
                if is_text(&inputtag) && (name.contains("user") || name.contains("email")) {
                    debug!("Using tag with name {name} for username");
                    payload.insert(name, &self.user_name);
                    username_found = true;
                }
            }
        }

        if !username_found || !pwd_found {
            let error_msg = "Failed to parse Ping IdP login form field(s)";
            panic!("{error_msg}");
        }

        let action = get_form_action(&soup);
        // NOTE: not sure if we want to continue with the original url in None case
        if let Some(action_str) = action
            && action_str.starts_with("/")
        {
            url = format!("https://{}:{}{action_str}", self.idp_host, self.idp_port);
        }
        // else {
        //     panic!();
        // }

        debug!(
            "Issuing authentication request to Ping IdP using uri {} verify {}",
            &url,
            self.do_verify_ssl_cert(),
        );
        let response = session
            .post(&url) //verify=self.do_verify_ssl_cert()
            .form(&payload)
            .send()
            .await
            .unwrap();
        let status_code = response.status();
        debug!("Response code: {status_code}");
        let resp_text = response.text().await.unwrap();
        if status_code != 200 {
            panic!(
                "POST to {url} returned non-200 http status.\n{}",
                &resp_text
            );
        }

        let soup = Html::parse_document(&resp_text);

        let mut assertion = "";
        for inputtag in soup.select(&selector) {
            if inputtag.attr("name") == Some("SAMLResponse") {
                debug!("SAMLResponse tag found");
                assertion = inputtag.attr("value").unwrap();
            }
        }

        if assertion.is_empty() {
            let exec_msg = "Failed to retrieve SAMLAssertion. An input tag named SAMLResponse was not identified in the Ping IdP authentication response";
            panic!("{exec_msg}");
        }

        assertion.to_string()
    }
}

// struct Redshift

async fn get_credentials(
    idp_host: &str,
    idp_port: u16,
    db_user: &str,
    password: SecretString,
    role_arn: String,
) -> Option<sts::types::Credentials> {
    // refresh method alias
    let ping_provider = PingCredentialsProvider::new(idp_host, idp_port, db_user, password);
    let saml_assertion = ping_provider.get_saml_assertion().await;

    // decode SAML assertion into xml format
    let ass_bytes = BASE64_STANDARD.decode(saml_assertion.as_bytes()).unwrap();
    let doc = str::from_utf8(&ass_bytes).unwrap();

    debug!("decoded SAML assertion into xml format");
    // NOTE could parse it as xml, but keeping it lightweighted
    let soup = Html::parse_document(doc);
    let selector = Selector::parse(r"saml\:AttributeValue").unwrap();
    let attrs = soup.select(&selector);

    // extract RoleArn and PrincipleArn from SAML assertion
    let role_pattern = re::compile(r"arn:aws:iam::\d*:role/\S+");
    let provider_pattern = re::compile(r"arn:aws:iam::\d*:saml-provider/\S+");
    let mut roles: HashMap<&str, String> = HashMap::new();
    debug!("searching SAML assertion for values matching patterns for RoleArn and PrincipalArn");
    // TODO: let user specify None as role and then pick the first one
    for attr in attrs {
        for value in attr.text() {
            let mut role = "";
            let mut provider = String::new();
            for arn_ in value.split(",") {
                let arn = arn_.trim();
                if role_pattern.is_match(arn) {
                    debug!("RoleArn pattern matched");
                    role = arn;
                }
                if provider_pattern.is_match(arn) {
                    debug!("PrincipleArn pattern matched");
                    provider = arn.to_string();
                }
            }
            if !role.is_empty() && !provider.is_empty() {
                roles.insert(role, provider);
            }
        }
    }
    debug!("Done reading SAML assertion attributes");
    debug!("{} roles identified in SAML assertion", roles.len());

    if roles.is_empty() {
        let exec_msg = "No roles were found in SAML assertion. Please verify IdP configuration provides ARNs in the SAML https://aws.amazon.com/SAML/Attributes/Role Attribute.";
        panic!("{exec_msg}");
    }
    debug!("User provided preferred_role, trying to use...");
    if !roles.contains_key(&*role_arn) {
        let exec_msg = "User specified preferred_role was not found in SAML assertion https://aws.amazon.com/SAML/Attributes/Role Attribute";
        panic!("{exec_msg}");
    }

    // empty config; no prior aws identity needed
    let config = aws_config::load_from_env().await;
    let client = sts::Client::new(&config);
    debug!(
        "Attempting to retrieve temporary AWS credentials using the SAML assertion, principal ARN, and role ARN."
    );
    let response = client
        .assume_role_with_saml()
        .set_principal_arn(roles.remove(&*role_arn)) // remove instead of get, so we move the value out and not get ref
        .set_role_arn(Some(role_arn))
        .saml_assertion(saml_assertion)
        .send()
        .await
        .unwrap();
    debug!("Extracting temporary AWS credentials from assume_role_with_saml response");

    response.credentials
}

fn main() -> anyhow::Result<(), Box<dyn std::error::Error>> {
    // inputs:
    let host = env::var("HOST")?;
    let port = env::var("PORT")?; // could be default
    let database = env::var("DATABASE")?;
    let query = "".to_string();

    let rt = Runtime::new()?;
    let (user, password) = rt.block_on(async {
        // inputs only used in async scope:
        let user = env::var("USER").unwrap().to_string();
        let password = SecretString::new(String::from(env::var("PWD").unwrap()).into_boxed_str());
        let cluster = env::var("CLUSTER").unwrap().to_string();
        let autocreate = false;
        let preferred_role = env::var("ROLE_ARN").unwrap().to_string();
        let idp_host = env::var("IDP_HOST").unwrap();

        let aws_credentials = get_credentials(&idp_host, 443, &user, password, preferred_role)
            .await
            .unwrap();

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
            .set_db_user(Some(user))
            .set_db_name(Some(database.clone()))
            .set_cluster_identifier(Some(cluster))
            .set_duration_seconds(Some(3600))
            .set_auto_create(Some(autocreate))
            .send()
            .await
            .unwrap(); //?

        let user = cluster_creds.db_user.unwrap();
        let password = cluster_creds.db_password.unwrap();
        (user, password)
    });

    let uri = format!("postgresql://{host}:{port}/{database}?cxprotocol=cursor");
    let mut redshift_url = reqwest::Url::parse(&uri).unwrap();
    // URL-encode credentials
    redshift_url.set_username(&user).unwrap();
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
