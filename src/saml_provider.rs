use std::collections::HashMap;
use std::future::Future;
use std::str;

// use aws_config;
use aws_sdk_sts as sts;
use base64::prelude::*;
use log::{debug, warn};
// use reqwest;
use scraper::{ElementRef, Html, Selector};
use secrecy::{ExposeSecret, SecretString};
use tokio::runtime::Runtime;

use crate::re;

/// Trait for identity providers that can supply a SAML assertion.
pub trait SamlProvider {
    /// Fetches and returns a base64-encoded SAML assertion from the IdP.
    fn get_saml_assertion(&self) -> impl Future<Output = String>;
}

/// Returns `true` if the input tag has `type="password"`.
fn is_password(inputtag: &ElementRef) -> bool {
    inputtag.attr("type") == Some("password")
}

/// Returns `true` if the input tag has `type="text"`.
fn is_text(inputtag: &ElementRef) -> bool {
    inputtag.attr("type") == Some("text")
}

/// Finds the first form `action` attribute whose method is POST (or unspecified).
/// Forms with an explicit non-POST method are skipped. Returns `None` if no
/// qualifying form is found.
fn get_form_action(soup: &Html) -> Option<&str> {
    // NOTE: selector case-insensitive; it will match both form and FORM
    let selector = Selector::parse("form").unwrap();

    for inputtag in soup.select(&selector) {
        let action = inputtag.attr("action");
        if action.is_some() {
            let method = inputtag.attr("method");
            // safe unwrap
            if method.is_some() && method.unwrap().to_uppercase() != "POST" {
                warn!("Found action, but method is not POST. Skipping.");
                continue;
            }
            return action;
        }
    }

    None
}

/// Obtains temporary AWS credentials by exchanging a SAML assertion for STS credentials.
///
/// Calls [`SamlProvider::get_saml_assertion`], decodes the assertion, extracts the
/// IAM role and principal ARNs, and calls `sts:AssumeRoleWithSAML` for `role_arn`.
///
/// # Panics
/// - If no IAM roles are found in the SAML assertion.
/// - If `role_arn` is not present among the roles in the assertion.
pub async fn get_credentials<T: SamlProvider>(
    provider: &T,
    role_arn: String,
) -> Option<sts::types::Credentials> {
    // refresh method alias
    let saml_assertion = provider.get_saml_assertion().await;

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

/// Extracts the SAMLResponse assertion value from the IdP authentication response HTML.
/// Panics if no `SAMLResponse` input tag is found.
pub fn parse_saml_assertion(html: &str) -> String {
    let soup = Html::parse_document(html);
    let selector = Selector::parse("INPUT").unwrap();
    let mut assertion = String::new();
    for inputtag in soup.select(&selector) {
        if inputtag.attr("name") == Some("SAMLResponse") {
            debug!("SAMLResponse tag found");
            assertion = inputtag.attr("value").unwrap().to_string();
        }
    }
    if assertion.is_empty() {
        panic!(
            "Failed to retrieve SAMLAssertion. An input tag named SAMLResponse was not identified in the Ping IdP authentication response"
        );
    }
    assertion
}

/// PingFederate identity provider plugin for SAML-based Redshift authentication.
///
/// See the [Amazon Redshift IAM docs](https://docs.aws.amazon.com/redshift/latest/mgmt/options-for-providing-iam-credentials.html)
/// for setup instructions.
#[derive(Debug)]
pub struct PingCredentialsProvider {
    partner_sp_id: String,
    idp_host: String,
    idp_port: u16,
    user_name: String,
    password: SecretString,
    /// When `true`, TLS certificate verification is disabled. Defaults to `false`.
    pub ssl_insecure: bool,
}

impl PingCredentialsProvider {
    /// Creates a new `PingCredentialsProvider`.
    ///
    /// - `partner_sp_id`: The SP entity ID sent to PingFederate. `None` defaults to
    ///   `"urn%3Aamazon%3Awebservices"`.
    /// - `idp_port`: Defaults to `443` when `None`.
    pub fn new(
        partner_sp_id_option: Option<impl ToString>,
        idp_host: impl ToString,
        idp_port: Option<u16>,
        user_name: impl ToString,
        password: SecretString,
    ) -> Self {
        // We could either accept pwd and create secretString here or force user to pass it
        let partner_sp_id = if let Some(partner_sp_id) = partner_sp_id_option {
            partner_sp_id.to_string()
        } else {
            "urn%3Aamazon%3Awebservices".to_string()
        };
        Self {
            partner_sp_id,
            idp_host: idp_host.to_string(),
            idp_port: idp_port.unwrap_or(443),
            user_name: user_name.to_string(),
            password,
            ssl_insecure: false,
        }
    }

    /// user getter
    pub fn user(&self) -> String {
        self.user_name.clone()
    }

    /// Returns `true` when TLS certificate verification is enabled (i.e. `ssl_insecure` is `false`).
    pub fn do_verify_ssl_cert(&self) -> bool {
        !self.ssl_insecure
    }

    /// Synchronously retrieves temporary AWS credentials for `preferred_role`.
    ///
    /// Drives the full SAML -> STS flow on a new Tokio runtime. Prefer the async
    /// [`get_credentials`] free function when already inside an async context.
    pub fn get_credentials(
        &self,
        preferred_role: impl ToString,
    ) -> Option<sts::types::Credentials> {
        let rt = Runtime::new().unwrap(); //?
        rt.block_on(async { get_credentials(self, preferred_role.to_string()).await })
    }

    /// Parses the IdP login page HTML, extracting the form submission payload and
    /// the form's action path. Panics if username or password fields cannot be found.
    fn parse_login_form(&self, html: &str) -> (HashMap<String, String>, Option<String>) {
        let soup = Html::parse_document(html);
        let selector = Selector::parse("INPUT").unwrap();
        let mut payload: HashMap<String, String> = HashMap::new();
        let mut username_found = false;
        let mut pwd_found = false;

        debug!(
            "Looking for username and password input tags in Ping IdP login page in order to build authentication request payload"
        );
        for inputtag in soup.select(&selector) {
            let name = inputtag.attr("name").unwrap_or("").to_string();
            let id_ = inputtag.attr("id").unwrap_or("");
            debug!("name={name} , id={id_}");

            if !username_found && is_text(&inputtag) && id_ == "username" {
                debug!("Using tag with name {name} for username");
                payload.insert(name, self.user());
                username_found = true;
            } else if is_password(&inputtag) && name.contains("pass") {
                debug!("Using tag with name {name} for password");
                if pwd_found {
                    panic!(
                        "Failed to parse Ping IdP login form. More than one password field was found on the Ping IdP login page"
                    );
                }
                payload.insert(name, self.password.expose_secret().to_string());
                pwd_found = true;
            } else if !name.is_empty() {
                let value = inputtag.attr("value").unwrap_or("").to_string();
                payload.insert(name, value);
            }
        }

        if !username_found {
            debug!(
                "username tag still not found, continuing search using secondary preferred tags"
            );
            for inputtag in soup.select(&selector) {
                let name = inputtag.attr("name").unwrap_or("").to_string();
                if is_text(&inputtag) && (name.contains("user") || name.contains("email")) {
                    debug!("Using tag with name {name} for username");
                    payload.insert(name, self.user());
                    username_found = true;
                }
            }
        }

        if !username_found || !pwd_found {
            panic!("Failed to parse Ping IdP login form field(s)");
        }

        let action = get_form_action(&soup).map(str::to_owned);
        (payload, action)
    }
}

impl SamlProvider for PingCredentialsProvider {
    /// Logs in to the PingFederate IdP and returns a base64-encoded SAML assertion.
    ///
    /// Issues a GET to the SSO start URL, parses the login form, submits credentials,
    /// and extracts the `SAMLResponse` value from the resulting page.
    ///
    /// # Panics
    /// - If the login form cannot be parsed or credentials fields are missing.
    /// - If the POST to the IdP returns a non-200 status.
    /// - If no `SAMLResponse` input is found in the response.
    async fn get_saml_assertion(&self) -> String {
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
        debug!("response length: {}", resp.content_length().unwrap_or(0));

        let resp_text = resp.text().await.unwrap();
        let (payload, action) = self.parse_login_form(&resp_text);

        // NOTE: not sure if we want to continue with the original url in None case
        if let Some(action_str) = action.as_deref()
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

        parse_saml_assertion(&resp_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _make_valid_ping_credentials_provider() -> PingCredentialsProvider {
        PingCredentialsProvider::new(
            None::<String>,
            "example.example.com",
            None,
            "user",
            SecretString::new("pwd".to_string().into_boxed_str()),
        )
    }

    // parse_login_form tests
    const LOGIN_PAGE_HTML: &str = r#"<html><body>
    <form action="/idp/authLogin" method="POST">
    <INPUT type="text" name="username" id="username" value="" />
    <INPUT type="password" name="pf.pass" value="" />
    <INPUT type="hidden" name="pf.ok" value="clicked" />
    </form>
    </body></html>"#;

    #[test]
    fn test_parse_login_form_extracts_credentials_and_hidden_fields() {
        let scp = _make_valid_ping_credentials_provider();
        let (payload, action) = scp.parse_login_form(LOGIN_PAGE_HTML);
        assert_eq!(payload.get("username").map(String::as_str), Some("user"));
        assert_eq!(payload.get("pf.pass").map(String::as_str), Some("pwd"));
        assert_eq!(payload.get("pf.ok").map(String::as_str), Some("clicked"));
        assert_eq!(action.as_deref(), Some("/idp/authLogin"));
    }

    #[test]
    fn test_parse_login_form_secondary_username_lookup() {
        let scp = _make_valid_ping_credentials_provider();
        // No id="username"; falls back to matching by name containing "user"
        let html = r#"<html><body><form action="/login">
        <INPUT type="text" name="user_email" value="" />
        <INPUT type="password" name="password" value="" />
        </form></body></html>"#;
        let (payload, _) = scp.parse_login_form(html);
        assert_eq!(payload.get("user_email").map(String::as_str), Some("user"));
    }

    #[test]
    #[should_panic(expected = "Failed to parse Ping IdP login form field(s)")]
    fn test_parse_login_form_missing_fields_panics() {
        let scp = _make_valid_ping_credentials_provider();
        scp.parse_login_form("<html><body><form></form></body></html>");
    }

    #[test]
    #[should_panic(expected = "More than one password field")]
    fn test_parse_login_form_duplicate_password_panics() {
        let scp = _make_valid_ping_credentials_provider();
        let html = r#"<html><body><form>
        <INPUT type="text" name="username" id="username" value="" />
        <INPUT type="password" name="pf.pass" value="" />
        <INPUT type="password" name="pf.pass2" value="" />
        </form></body></html>"#;
        scp.parse_login_form(html);
    }

    // get_form_action tests

    fn _parse(html: &str) -> Html {
        Html::parse_document(html)
    }

    #[test]
    fn test_get_form_action_returns_action_for_post_form() {
        let soup =
            _parse(r#"<html><body><form action="/submit" method="POST"></form></body></html>"#);
        assert_eq!(get_form_action(&soup), Some("/submit"));
    }

    #[test]
    fn test_get_form_action_returns_action_when_no_method_attribute() {
        // method is None -> the non-POST check doesn't fire -> action is returned
        let soup = _parse(r#"<html><body><form action="/submit"></form></body></html>"#);
        assert_eq!(get_form_action(&soup), Some("/submit"));
    }

    #[test]
    fn test_get_form_action_skips_non_post_form() {
        let soup =
            _parse(r#"<html><body><form action="/submit" method="GET"></form></body></html>"#);
        assert_eq!(get_form_action(&soup), None);
    }

    #[test]
    fn test_get_form_action_returns_none_when_no_action() {
        let soup = _parse(r#"<html><body><form method="POST"></form></body></html>"#);
        assert_eq!(get_form_action(&soup), None);
    }

    #[test]
    fn test_get_form_action_returns_none_when_no_form() {
        let soup = _parse(r#"<html><body></body></html>"#);
        assert_eq!(get_form_action(&soup), None);
    }

    #[test]
    fn test_get_form_action_skips_non_post_returns_second_form_action() {
        // First form has method=GET (skipped), second has a valid action
        let soup = _parse(
            r#"<html><body>
            <form action="/bad" method="GET"></form>
            <form action="/good" method="POST"></form>
        </body></html>"#,
        );
        assert_eq!(get_form_action(&soup), Some("/good"));
    }
}
