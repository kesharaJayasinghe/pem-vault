//! OAuth2 loopback + PKCE sign-in for the `drive.appdata` scope; refresh token kept in the OS keyring.
//!
//! Flow (Google "installed app" loopback): bind `127.0.0.1:<random port>`, open the consent
//! page with a PKCE S256 challenge and a random `state`, accept the single redirect, exchange
//! the code for tokens and store only the refresh token in the OS keychain.

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

/// The only OAuth scope pem-vault ever requests.
pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";

const KEYRING_SERVICE: &str = "pem-vault-cli";
const KEYRING_ACCOUNT: &str = "google-drive-refresh-token";
const ENV_CLIENT_ID: &str = "PEM_VAULT_CLIENT_ID";
const ENV_CLIENT_SECRET: &str = "PEM_VAULT_CLIENT_SECRET";
const SETUP_HINT: &str = "see README → Google Cloud setup, step 5";

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_HEAD: usize = 8 * 1024;

// ---- Configuration (P5.2) --------------------------------------------------------------------

/// OAuth client credentials. Deliberately not `Debug`: the secret must never be printed.
pub struct Config {
    client_id: String,
    client_secret: Zeroizing<String>,
}

impl Config {
    /// Reads `PEM_VAULT_CLIENT_ID` and `PEM_VAULT_CLIENT_SECRET` from the environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let required = |key: &str| {
            get(key)
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| anyhow!("{key} is not set ({SETUP_HINT})"))
        };
        Ok(Self {
            client_id: required(ENV_CLIENT_ID)?,
            client_secret: Zeroizing::new(required(ENV_CLIENT_SECRET)?),
        })
    }
}

/// OAuth endpoints; overridable so tests can point them at a mock server.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub authorize: String,
    pub token: String,
    pub revoke: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            authorize: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            revoke: "https://oauth2.googleapis.com/revoke".into(),
        }
    }
}

/// HTTP client for Google APIs: HTTPS only, with timeouts.
pub fn http_client() -> Result<Client> {
    Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
        .context("cannot initialize the HTTPS client")
}

// ---- Refresh-token storage (P5.1) ------------------------------------------------------------

/// Where the refresh token lives. Production uses the OS keychain; tests use memory.
pub trait TokenStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>>;
    fn save(&self, refresh_token: &str) -> Result<()>;
    /// Removes the token; succeeds if there was none.
    fn delete(&self) -> Result<()>;
}

/// macOS Keychain / Windows Credential Manager / Linux Secret Service, via `keyring`.
pub struct KeyringStore;

impl KeyringStore {
    fn entry() -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .context("the OS credential store is unavailable")
    }
}

impl TokenStore for KeyringStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>> {
        match Self::entry()?.get_password() {
            Ok(token) => Ok(Some(Zeroizing::new(token))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context("cannot read the Google session from the OS credential store"),
        }
    }

    fn save(&self, refresh_token: &str) -> Result<()> {
        Self::entry()?
            .set_password(refresh_token)
            .context("cannot save the Google session to the OS credential store")
    }

    fn delete(&self) -> Result<()> {
        match Self::entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => {
                Err(e).context("cannot remove the Google session from the OS credential store")
            }
        }
    }
}

// ---- PKCE & state ----------------------------------------------------------------------------

struct Pkce {
    verifier: Zeroizing<String>,
    challenge: String,
}

impl Pkce {
    /// RFC 7636: 32 random bytes → 43-char base64url verifier; S256 challenge.
    fn generate() -> Result<Self> {
        Ok(Self::from_verifier(random_urlsafe::<32>()?))
    }

    fn from_verifier(verifier: Zeroizing<String>) -> Self {
        let challenge = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

fn random_urlsafe<const N: usize>() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut_slice())
        .map_err(|_| anyhow!("the operating system's random number generator failed"))?;
    Ok(Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD.encode(bytes.as_slice()),
    ))
}

fn authorize_url(
    endpoints: &Endpoints,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> Result<Url> {
    Url::parse_with_params(
        &endpoints.authorize,
        [
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", SCOPE),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", state),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ],
    )
    .context("invalid authorization endpoint URL")
}

// ---- Loopback callback -----------------------------------------------------------------------

/// Interprets the request target of one loopback request.
///
/// - `Ok(None)`: not the OAuth redirect (e.g. `/favicon.ico`); keep waiting.
/// - `Ok(Some(code))`: a valid redirect whose `state` matches.
/// - `Err`: a redirect with the wrong `state`, an `error=` parameter, or no code.
fn parse_callback(target: &str, expected_state: &str) -> Result<Option<Zeroizing<String>>> {
    let url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| anyhow!("malformed sign-in redirect"))?;
    if url.path() != "/" {
        return Ok(None);
    }
    let (mut state, mut code, mut error) = (None, None, None);
    for (key, value) in url.query_pairs() {
        match &*key {
            "state" => state = Some(value.into_owned()),
            "code" => code = Some(Zeroizing::new(value.into_owned())),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    if state.is_none() && code.is_none() && error.is_none() {
        return Ok(None);
    }
    if state.as_deref() != Some(expected_state) {
        bail!("sign-in redirect had an unexpected state parameter; aborting (possible forgery)");
    }
    if let Some(error) = error {
        let error = if error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            error
        } else {
            "unknown_error".into()
        };
        bail!("Google sign-in was not completed ({error})");
    }
    match code {
        Some(code) if !code.is_empty() => Ok(Some(code)),
        _ => bail!("sign-in redirect did not include an authorization code"),
    }
}

/// Waits for the OAuth redirect on `listener`, answering each request with a small page.
async fn wait_for_callback(
    listener: &TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<Zeroizing<String>> {
    let wait = async {
        loop {
            let (mut stream, _) = listener.accept().await.context("sign-in listener failed")?;
            let Ok(Some(target)) = read_request_target(&mut stream).await else {
                respond(&mut stream, "404 Not Found", "Not found.").await;
                continue;
            };
            match parse_callback(&target, expected_state) {
                Ok(None) => respond(&mut stream, "404 Not Found", "Not found.").await,
                Ok(Some(code)) => {
                    respond(
                        &mut stream,
                        "200 OK",
                        "pem-vault is signed in to Google. You can close this tab.",
                    )
                    .await;
                    return Ok(code);
                }
                Err(e) => {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        "Sign-in failed. Return to the terminal for details.",
                    )
                    .await;
                    return Err(e);
                }
            }
        }
    };
    tokio::time::timeout(timeout, wait).await.map_err(|_| {
        anyhow!(
            "timed out after {} minutes waiting for Google sign-in",
            timeout.as_secs() / 60
        )
    })?
}

/// Reads an HTTP request head and returns the target of a `GET` request line.
async fn read_request_target(stream: &mut TcpStream) -> Result<Option<String>> {
    let mut head = Zeroizing::new(Vec::with_capacity(1024));
    let mut chunk = [0u8; 1024];
    let read = async {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut chunk).await?;
            if n == 0 || head.len() + n > MAX_REQUEST_HEAD {
                break;
            }
            head.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, std::io::Error>(())
    };
    tokio::time::timeout(CONNECTION_READ_TIMEOUT, read).await??;
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.lines().next().unwrap_or_default().split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) if target.starts_with('/') => Ok(Some(target.to_owned())),
        _ => Ok(None),
    }
}

async fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>pem-vault</title>\
         <p style=\"font:16px system-ui;margin:3em\">{message}</p>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    // Best effort: the browser tab's rendering doesn't affect the sign-in result.
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

// ---- Token endpoint --------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

enum TokenError {
    /// The refresh token is expired or revoked (every ~7 days while the app is in Testing).
    InvalidGrant,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for TokenError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// Access and (optionally) refresh token, both scrubbed on drop.
struct Tokens {
    access: Zeroizing<String>,
    refresh: Option<Zeroizing<String>>,
}

// ---- Sign-in orchestration (P5.3–P5.5) -------------------------------------------------------

/// Google sign-in and session management.
pub struct Auth<'a, S: TokenStore> {
    http: &'a Client,
    config: &'a Config,
    store: &'a S,
    endpoints: Endpoints,
}

impl<'a, S: TokenStore> Auth<'a, S> {
    pub fn new(http: &'a Client, config: &'a Config, store: &'a S) -> Self {
        Self {
            http,
            config,
            store,
            endpoints: Endpoints::default(),
        }
    }

    #[cfg(test)]
    fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Interactive browser sign-in (`pem-vault auth`). Stores the refresh token and returns an
    /// access token so a command that triggered re-authentication can continue.
    pub async fn sign_in(&self) -> Result<Zeroizing<String>> {
        self.sign_in_with(|url| {
            eprintln!("[+] Opening your browser to sign in to Google…");
            eprintln!("    If it doesn't open, visit:\n    {url}");
            if webbrowser::open(url).is_err() {
                eprintln!("[!] Could not open a browser automatically");
            }
        })
        .await
    }

    async fn sign_in_with(&self, open: impl FnOnce(&str)) -> Result<Zeroizing<String>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("cannot start the local sign-in listener")?;
        let redirect_uri = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
        let pkce = Pkce::generate()?;
        let state = random_urlsafe::<16>()?;
        let url = authorize_url(
            &self.endpoints,
            &self.config.client_id,
            &redirect_uri,
            &pkce.challenge,
            &state,
        )?;

        open(url.as_str());
        let code = wait_for_callback(&listener, &state, CALLBACK_TIMEOUT).await?;
        drop(listener);

        let tokens = self
            .token_request(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", &pkce.verifier),
                ("redirect_uri", &redirect_uri),
            ])
            .await
            .map_err(|e| match e {
                TokenError::InvalidGrant => {
                    anyhow!("Google rejected the sign-in code (invalid_grant); run `pem-vault auth` again")
                }
                TokenError::Other(e) => e,
            })?;
        let refresh = tokens.refresh.ok_or_else(|| {
            anyhow!("Google did not return a refresh token; remove pem-vault's access at https://myaccount.google.com/permissions and run `pem-vault auth` again")
        })?;
        self.store.save(&refresh)?;
        eprintln!("[+] Signed in; Google session saved to the OS credential store");
        Ok(tokens.access)
    }

    /// Returns a fresh access token, refreshing with the stored refresh token.
    ///
    /// If there is no session, or it has expired (`invalid_grant`), the stale token is removed
    /// and `confirm_reauth` decides whether to sign in again right away.
    pub async fn access_token(
        &self,
        confirm_reauth: impl FnOnce(&str) -> bool,
    ) -> Result<Zeroizing<String>> {
        let Some(refresh) = self.store.load()? else {
            return self
                .reauth(
                    confirm_reauth,
                    "Not signed in to Google. Sign in now?",
                    "Not signed in",
                )
                .await;
        };
        match self
            .token_request(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)])
            .await
        {
            Ok(tokens) => {
                if let Some(rotated) = tokens.refresh {
                    self.store.save(&rotated)?;
                }
                Ok(tokens.access)
            }
            Err(TokenError::InvalidGrant) => {
                self.store.delete()?;
                self.reauth(
                    confirm_reauth,
                    "Google session expired. Sign in again now?",
                    "Session expired or revoked",
                )
                .await
            }
            Err(TokenError::Other(e)) => Err(e),
        }
    }

    async fn reauth(
        &self,
        confirm: impl FnOnce(&str) -> bool,
        question: &str,
        reason: &str,
    ) -> Result<Zeroizing<String>> {
        if confirm(question) {
            self.sign_in().await
        } else {
            bail!("{reason}. Run `pem-vault auth`.")
        }
    }

    /// POSTs to the token endpoint with client credentials. Never echoes response bodies.
    async fn token_request(&self, params: &[(&str, &str)]) -> Result<Tokens, TokenError> {
        let mut form: Vec<(&str, &str)> = params.to_vec();
        form.push(("client_id", &self.config.client_id));
        form.push(("client_secret", &self.config.client_secret));

        let response = self
            .http
            .post(&self.endpoints.token)
            .form(&form)
            .send()
            .await
            .context("cannot reach Google's token endpoint")?;
        let status = response.status();
        if !status.is_success() {
            let code = response
                .json::<OAuthError>()
                .await
                .map(|e| e.error)
                .unwrap_or_default();
            return Err(match (status, code.as_str()) {
                (StatusCode::BAD_REQUEST, "invalid_grant") => TokenError::InvalidGrant,
                (_, "invalid_client" | "unauthorized_client") => TokenError::Other(anyhow!(
                    "Google rejected the OAuth client; check {ENV_CLIENT_ID} and {ENV_CLIENT_SECRET} ({SETUP_HINT})"
                )),
                _ => TokenError::Other(anyhow!(
                    "Google's token endpoint returned HTTP {status}{}",
                    if code.is_empty() {
                        String::new()
                    } else {
                        format!(" ({code})")
                    }
                )),
            });
        }

        let body: TokenResponse = response
            .json()
            .await
            .map_err(|_| anyhow!("unexpected response from Google's token endpoint"))?;
        let tokens = Tokens {
            access: Zeroizing::new(body.access_token),
            refresh: body.refresh_token.map(Zeroizing::new),
        };
        // With granular consent the user can untick the Drive permission.
        if let Some(scope) = body.scope
            && !scope.split(' ').any(|s| s == SCOPE)
        {
            return Err(TokenError::Other(anyhow!(
                "the Google Drive app-data permission was not granted; run `pem-vault auth` and allow it"
            )));
        }
        Ok(tokens)
    }
}

/// Revokes the refresh token at Google (best effort) and removes it locally.
///
/// Needs no OAuth client credentials: revocation takes only the token itself.
pub async fn logout<S: TokenStore>(http: &Client, store: &S) -> Result<()> {
    logout_at(http, store, &Endpoints::default().revoke).await
}

async fn logout_at<S: TokenStore>(http: &Client, store: &S, revoke_url: &str) -> Result<()> {
    let Some(refresh) = store.load()? else {
        eprintln!("[+] Not signed in; nothing to do");
        return Ok(());
    };
    let revoked = http
        .post(revoke_url)
        .form(&[("token", refresh.as_str())])
        .send()
        .await
        .map(|r| r.status().is_success());
    match revoked {
        Ok(true) => eprintln!("[+] Revoked pem-vault's access at Google"),
        _ => eprintln!(
            "[!] Could not revoke the token at Google; remove access manually at https://myaccount.google.com/permissions"
        ),
    }
    store.delete()?;
    eprintln!("[+] Removed the Google session from the OS credential store");
    Ok(())
}

/// Asks on the terminal whether to sign in again. Returns `false` without a TTY on stdin, so
/// scripted runs fail with a clear message instead of waiting on a browser.
pub fn confirm_on_terminal(question: &str) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("[!] {question} [Y/n] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "" | "y" | "yes"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ---- Test doubles ---------------------------------------------------------------------

    #[derive(Default)]
    struct MemoryStore(RefCell<Option<String>>);

    impl MemoryStore {
        fn with(token: &str) -> Self {
            Self(RefCell::new(Some(token.into())))
        }
        fn get(&self) -> Option<String> {
            self.0.borrow().clone()
        }
    }

    impl TokenStore for MemoryStore {
        fn load(&self) -> Result<Option<Zeroizing<String>>> {
            Ok(self.0.borrow().clone().map(Zeroizing::new))
        }
        fn save(&self, token: &str) -> Result<()> {
            *self.0.borrow_mut() = Some(token.into());
            Ok(())
        }
        fn delete(&self) -> Result<()> {
            *self.0.borrow_mut() = None;
            Ok(())
        }
    }

    fn config() -> Config {
        Config {
            client_id: "test-client.apps.googleusercontent.com".into(),
            client_secret: Zeroizing::new("test-secret".into()),
        }
    }

    fn endpoints(server: &MockServer) -> Endpoints {
        Endpoints {
            authorize: format!("{}/auth", server.uri()),
            token: format!("{}/token", server.uri()),
            revoke: format!("{}/revoke", server.uri()),
        }
    }

    fn token_json(refresh: Option<&str>, scope: Option<&str>) -> serde_json::Value {
        let mut body = serde_json::json!({ "access_token": "access-123", "expires_in": 3599, "token_type": "Bearer" });
        if let Some(r) = refresh {
            body["refresh_token"] = r.into();
        }
        if let Some(s) = scope {
            body["scope"] = s.into();
        }
        body
    }

    fn never(_: &str) -> bool {
        false
    }

    // ---- Config -----------------------------------------------------------------------------

    #[test]
    fn config_requires_both_variables() {
        let env = |pairs: &'static [(&str, &str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert!(
            Config::from_lookup(env(&[(ENV_CLIENT_ID, "id"), (ENV_CLIENT_SECRET, "s")])).is_ok()
        );
        let err = Config::from_lookup(env(&[(ENV_CLIENT_SECRET, "s")]))
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains(ENV_CLIENT_ID) && err.contains("README"),
            "{err}"
        );
        let err = Config::from_lookup(env(&[(ENV_CLIENT_ID, "id"), (ENV_CLIENT_SECRET, "  ")]))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains(ENV_CLIENT_SECRET), "{err}");
    }

    // ---- PKCE & authorize URL ------------------------------------------------------------------

    #[test]
    fn pkce_matches_rfc7636_appendix_b() {
        let pkce = Pkce::from_verifier(Zeroizing::new(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
        ));
        assert_eq!(
            pkce.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_pkce_and_state_are_random_and_well_formed() {
        let (a, b) = (Pkce::generate().unwrap(), Pkce::generate().unwrap());
        assert_eq!(a.verifier.len(), 43); // RFC 7636 requires 43..=128
        assert_ne!(*a.verifier, *b.verifier);
        assert_ne!(
            *random_urlsafe::<16>().unwrap(),
            *random_urlsafe::<16>().unwrap()
        );
    }

    #[test]
    fn authorize_url_has_required_parameters() {
        let url = authorize_url(
            &Endpoints::default(),
            "cid",
            "http://127.0.0.1:5555",
            "chal",
            "st",
        )
        .unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["scope"], SCOPE);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], "chal");
        assert_eq!(q["state"], "st");
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["prompt"], "consent");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:5555");
        assert_eq!(q["response_type"], "code");
    }

    // ---- Callback parsing (P5.6) ----------------------------------------------------------------

    #[test]
    fn callback_with_matching_state_returns_code() {
        let code = parse_callback("/?state=abc&code=4%2F0Ab-xyz&scope=x", "abc")
            .unwrap()
            .unwrap();
        assert_eq!(code.as_str(), "4/0Ab-xyz");
    }

    #[test]
    fn callback_with_wrong_or_missing_state_is_rejected() {
        assert!(
            parse_callback("/?state=evil&code=c", "abc")
                .unwrap_err()
                .to_string()
                .contains("state")
        );
        assert!(parse_callback("/?code=c", "abc").is_err());
    }

    #[test]
    fn callback_access_denied_is_reported() {
        let err = parse_callback("/?state=abc&error=access_denied", "abc")
            .unwrap_err()
            .to_string();
        assert!(err.contains("access_denied"), "{err}");
        // Unexpected characters in the error value are not echoed.
        let err = parse_callback("/?state=abc&error=%3Cscript%3E", "abc")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown_error") && !err.contains("script"),
            "{err}"
        );
    }

    #[test]
    fn callback_without_code_is_rejected() {
        assert!(parse_callback("/?state=abc", "abc").is_err());
        assert!(parse_callback("/?state=abc&code=", "abc").is_err());
    }

    #[test]
    fn unrelated_requests_are_ignored() {
        assert!(parse_callback("/favicon.ico", "abc").unwrap().is_none());
        assert!(parse_callback("/", "abc").unwrap().is_none());
    }

    // ---- Loopback listener ------------------------------------------------------------------------

    async fn get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn listener_skips_stray_requests_then_accepts_callback() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = tokio::spawn(async move {
            let favicon = get(port, "/favicon.ico").await;
            let callback = get(port, "/?state=st&code=the-code").await;
            (favicon, callback)
        });
        let code = wait_for_callback(&listener, "st", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(code.as_str(), "the-code");
        let (favicon, callback) = client.await.unwrap();
        assert!(favicon.starts_with("HTTP/1.1 404"));
        assert!(callback.starts_with("HTTP/1.1 200") && callback.contains("close this tab"));
    }

    #[tokio::test]
    async fn listener_times_out() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let err = wait_for_callback(&listener, "st", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    // ---- Full sign-in against a mock token endpoint ---------------------------------------------

    /// Plays the browser: follows the authorize URL's redirect_uri with its state.
    fn fake_browser(code: &'static str) -> impl FnOnce(&str) {
        move |url: &str| {
            let url = Url::parse(url).unwrap();
            let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            let redirect = Url::parse(&q["redirect_uri"]).unwrap();
            let target = format!("/?state={}&code={code}", q["state"]);
            tokio::spawn(async move { get(redirect.port().unwrap(), &target).await });
        }
    }

    #[tokio::test]
    async fn sign_in_exchanges_code_and_saves_refresh_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=the-code"))
            .and(body_string_contains("code_verifier="))
            .and(body_string_contains(
                "redirect_uri=http%3A%2F%2F127.0.0.1%3A",
            ))
            .and(body_string_contains("client_secret=test-secret"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(token_json(Some("refresh-1"), Some(SCOPE))),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::default());
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        let access = auth.sign_in_with(fake_browser("the-code")).await.unwrap();
        assert_eq!(access.as_str(), "access-123");
        assert_eq!(store.get().as_deref(), Some("refresh-1"));
    }

    #[tokio::test]
    async fn sign_in_without_refresh_token_fails_and_saves_nothing() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_json(None, Some(SCOPE))))
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::default());
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        let err = auth.sign_in_with(fake_browser("c")).await.unwrap_err();
        assert!(err.to_string().contains("refresh token"), "{err}");
        assert!(store.get().is_none());
    }

    #[tokio::test]
    async fn sign_in_without_drive_scope_fails_and_saves_nothing() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(token_json(Some("r"), Some("openid email"))),
            )
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::default());
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        let err = auth.sign_in_with(fake_browser("c")).await.unwrap_err();
        assert!(
            err.to_string().contains("permission was not granted"),
            "{err}"
        );
        assert!(store.get().is_none());
    }

    // ---- Refresh (P5.4) -------------------------------------------------------------------------

    #[tokio::test]
    async fn access_token_refreshes_with_stored_token() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=refresh-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_json(None, Some(SCOPE))))
            .expect(1)
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::with("refresh-1"));
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        assert_eq!(
            auth.access_token(never).await.unwrap().as_str(),
            "access-123"
        );
        assert_eq!(store.get().as_deref(), Some("refresh-1"));
    }

    #[tokio::test]
    async fn expired_session_is_deleted_and_reported_when_reauth_declined() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant", "error_description": "Token has been expired or revoked."
            })))
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::with("stale"));
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        let asked = std::cell::Cell::new(false);
        let err = auth
            .access_token(|q| {
                asked.set(q.contains("expired"));
                false
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(asked.get(), "the user was not asked to sign in again");
        assert!(
            err.contains("expired") && err.contains("pem-vault auth"),
            "{err}"
        );
        assert!(store.get().is_none(), "stale token was not removed");
    }

    #[tokio::test]
    async fn missing_session_is_reported_when_reauth_declined() {
        let (http, config, store) = (Client::new(), config(), MemoryStore::default());
        let auth = Auth::new(&http, &config, &store);
        let err = auth.access_token(never).await.unwrap_err().to_string();
        assert!(err.contains("Not signed in"), "{err}");
    }

    #[tokio::test]
    async fn rejected_client_credentials_give_setup_hint_without_body() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client", "error_description": "SECRET-DETAIL"
            })))
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::with("r"));
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        let err = auth.access_token(never).await.unwrap_err().to_string();
        assert!(err.contains(ENV_CLIENT_ID), "{err}");
        assert!(
            !err.contains("SECRET-DETAIL"),
            "response body leaked into error: {err}"
        );
        assert_eq!(
            store.get().as_deref(),
            Some("r"),
            "token must survive non-grant errors"
        );
    }

    #[tokio::test]
    async fn rotated_refresh_token_is_saved() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(token_json(Some("refresh-2"), None)),
            )
            .mount(&server)
            .await;
        let (http, config, store) = (Client::new(), config(), MemoryStore::with("refresh-1"));
        let auth = Auth::new(&http, &config, &store).with_endpoints(endpoints(&server));

        auth.access_token(never).await.unwrap();
        assert_eq!(store.get().as_deref(), Some("refresh-2"));
    }

    // ---- Logout (P5.5) --------------------------------------------------------------------------

    #[tokio::test]
    async fn logout_when_signed_out_is_a_no_op() {
        let server = MockServer::start().await;
        let (http, store) = (Client::new(), MemoryStore::default());
        logout_at(&http, &store, &endpoints(&server).revoke)
            .await
            .unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn logout_revokes_and_deletes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token=refresh-1"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let (http, store) = (Client::new(), MemoryStore::with("refresh-1"));

        logout_at(&http, &store, &endpoints(&server).revoke)
            .await
            .unwrap();
        assert!(store.get().is_none());
    }

    #[tokio::test]
    async fn logout_deletes_even_if_revocation_fails() {
        let server = MockServer::start().await;
        Mock::given(path("/revoke"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let (http, store) = (Client::new(), MemoryStore::with("refresh-1"));

        logout_at(&http, &store, &endpoints(&server).revoke)
            .await
            .unwrap();
        assert!(store.get().is_none());
    }
}
