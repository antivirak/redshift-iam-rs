# Changelog

## [0.3.1]

### Changed

- Pinned only the major version for most packages. I’d rather proactively pin/fix once something breaks than strictly pin the minor version, especially when the library will most likely work with newer ones as well.

## [0.3.0]

### ⚠ Breaking Changes

- **`read_sql` feature added**, and the `Redshift.execute()` or `read_sql` function is available only when the feature is enabled.

### Added

- **`redshift_to_postgres`** function added to exchange IAM/SAML identity for temporary Redshift credentials, returning a PostgreSQL JDBC-like connection string.

### Changed

- **Added new `RedshiftIamError`** for the crate. It is used instead of ConnectorXOutError.

## [0.2.1]

### Bugfix
- README file had wrong first argument to PingCredentialsProvider constructor.

## [0.2.0]

### ⚠ Breaking Changes

- **`PingCredentialsProvider::new` signature changed.**
  The first argument was `Option<impl ToString>` (the `PartnerSpId` value); it is now
  `&HashMap<String, Cow<str>>` (the full set of connection parameters parsed from the URI).
  `PartnerSpId` is now read from the map under the key `"partnerspid"` and still defaults
  to `"urn%3Aamazon%3Awebservices"` when absent.

  **Before (0.1.x):**
  ```rust
  PingCredentialsProvider::new(
      Some("urn%3Aamazon%3Awebservices"), // or None
      "pingfed.example.com",
      None,
      "alice",
      password,
  )
  ```

  **After (0.2.0):**
  ```rust
  use std::borrow::Cow;
  use std::collections::HashMap;

  let mut params: HashMap<String, Cow<str>> = HashMap::new();
  // optional — omit to use the default PartnerSpId
  params.insert("partnerspid".into(), Cow::Borrowed("urn%3Aamazon%3Awebservices"));

  PingCredentialsProvider::new(
      &params,
      "pingfed.example.com",
      None,
      "alice",
      password,
  )
  ```

- **`SamlProvider` trait is now object-safe** and must be implemented with
  `#[async_trait::async_trait]`. The `get_saml_assertion` method was previously
  declared as `fn … -> impl Future<Output = String>`; it is now a plain `async fn`.

  ```rust
  // Before
  impl SamlProvider for MyProvider {
      fn get_saml_assertion(&self) -> impl Future<Output = String> { … }
  }

  // After
  #[async_trait::async_trait]
  impl SamlProvider for MyProvider {
      async fn get_saml_assertion(&self) -> String { … }
  }
  ```

- **`parse_saml_assertion` made private.** Even though the "Active Directory Federation Services" provider will use similar function to parse SAML response; the other ones will use very different ones. It makes little sense to keep the function public, when it can be used with Ping only.

- **`get_credentials` uses dynamic dispatch.** The signature changed from
  `get_credentials<T: SamlProvider>(provider: &T, …)` to
  `get_credentials(provider: &dyn SamlProvider, …)`.

### Added

- **`PluginName` enum** — closed set of supported SAML provider variants parsed
  from the `Plugin_Name` JDBC-like URI parameter:
  `PingCredentialsProvider`, `OktaCredentialsProvider`,
  `BrowserSamlCredentialsProvider`, `BrowserAzureCredentialsProvider`,
  `AzureCredentialsProvider`, `AdfsCredentialsProvider`,
  `CustomCredentialsProvider`, `UnknownCredentialsProvider`.
  The optional `com.amazon.redshift.plugin.` package prefix is stripped
  automatically. Comparison is case-insensitive.

- **`register_provider(plugin: PluginName, factory)`** — registers a
  `Box<dyn SamlProvider>` factory for a `PluginName` variant. Must be called
  once at startup for any variant other than the built-in
  `PingCredentialsProvider`. The factory signature is:
  ```rust
  fn(&HashMap<String, Cow<str>>, &str, Option<u16>, &str, SecretString)
      -> Box<dyn SamlProvider>
  ```
  The first argument is the full map of lowercased URI query parameters,
  giving each provider access to its own extra keys (e.g. `app_id` for Okta,
  `idp_tenant` / `client_id` for Azure).

- **`async-trait` dependency** — required for implementing `SamlProvider` on
  custom types.

### Changed

- `PingCredentialsProvider` is pre-registered in the global registry; no call
  to `register_provider` is needed to use it.

---

## [0.1.2] - previous release

Baseline release. See repository history for details.
