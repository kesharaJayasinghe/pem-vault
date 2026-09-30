//! Google Drive v3 REST client scoped to `appDataFolder`; implements the `Store` trait.
//!
//! Only ever handles ciphertext envelopes. Every request is limited to the hidden
//! `appDataFolder` space, which the `drive.appdata` scope confines the app to anyway.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use zeroize::Zeroizing;

const META_BASE: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD_BASE: &str = "https://www.googleapis.com/upload/drive/v3";
const FILE_FIELDS: &str = "id,name,size,modifiedTime";
const LIST_FIELDS: &str = "nextPageToken,files(id,name,size,modifiedTime)";
const PAGE_SIZE: &str = "100";

/// Largest envelope `download` accepts (max plaintext 1 MiB + 65-byte overhead, with headroom).
pub const MAX_DOWNLOAD: usize = 2 * 1024 * 1024;

const MAX_ATTEMPTS: u32 = 3;
const RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

/// Metadata of one file in `appDataFolder`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFile {
    pub id: String,
    pub name: String,
    /// Drive returns the size as a decimal string.
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    pub modified_time: Option<String>,
}

impl DriveFile {
    pub fn size(&self) -> Option<u64> {
        self.size.as_deref()?.parse().ok()
    }
}

#[cfg(test)]
impl DriveFile {
    pub fn for_test(id: &str, name: &str, size: usize) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            size: Some(size.to_string()),
            modified_time: Some("2026-09-30T06:24:05.000Z".into()),
        }
    }
}

/// Remote storage for encrypted envelopes. `DriveClient` in production; a fake in tests.
pub trait Store {
    /// All vault files, following pagination.
    async fn list(&self) -> Result<Vec<DriveFile>>;
    /// Every file with exactly this Drive name. Callers must treat more than one as an error.
    async fn find(&self, drive_name: &str) -> Result<Vec<DriveFile>>;
    async fn create(&self, drive_name: &str, envelope: &[u8]) -> Result<DriveFile>;
    /// Replaces the content of an existing file, keeping its ID.
    async fn update(&self, file_id: &str, envelope: &[u8]) -> Result<DriveFile>;
    async fn download(&self, file_id: &str) -> Result<Vec<u8>>;
    /// Permanent: files in `appDataFolder` cannot be trashed.
    async fn delete(&self, file_id: &str) -> Result<()>;
}

/// Google Drive v3 client for `appDataFolder`.
pub struct DriveClient {
    http: Client,
    access_token: Zeroizing<String>,
    meta_base: String,
    upload_base: String,
    retry_base_delay: Duration,
}

impl DriveClient {
    pub fn new(http: Client, access_token: Zeroizing<String>) -> Self {
        Self {
            http,
            access_token,
            meta_base: META_BASE.into(),
            upload_base: UPLOAD_BASE.into(),
            retry_base_delay: RETRY_BASE_DELAY,
        }
    }

    #[cfg(test)]
    fn for_mock(base: &str) -> Self {
        Self {
            http: Client::new(),
            access_token: Zeroizing::new("test-token".into()),
            meta_base: format!("{base}/drive/v3"),
            upload_base: format!("{base}/upload/drive/v3"),
            retry_base_delay: Duration::from_millis(1),
        }
    }

    async fn query_files(&self, q: &str) -> Result<Vec<DriveFile>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Page {
            #[serde(default)]
            files: Vec<DriveFile>,
            next_page_token: Option<String>,
        }

        let url = format!("{}/files", self.meta_base);
        let mut files = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let response = self
                .send("list vault files", || {
                    let mut query = vec![
                        ("spaces", "appDataFolder"),
                        ("q", q),
                        ("fields", LIST_FIELDS),
                        ("pageSize", PAGE_SIZE),
                    ];
                    if let Some(token) = &page_token {
                        query.push(("pageToken", token));
                    }
                    self.http.get(&url).query(&query)
                })
                .await?;
            let page: Page = response
                .json()
                .await
                .context("unexpected response from Google Drive (list)")?;
            files.extend(page.files);
            match page.next_page_token {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => return Ok(files),
            }
        }
    }

    /// Sends a request built by `build`, with bearer auth, retrying transient failures
    /// (429, 5xx, 403 rate limits, timeouts) with exponential backoff and jitter.
    async fn send(&self, action: &str, build: impl Fn() -> RequestBuilder) -> Result<Response> {
        let mut delay = self.retry_base_delay;
        for attempt in 1..=MAX_ATTEMPTS {
            let last = attempt == MAX_ATTEMPTS;
            match build().bearer_auth(self.access_token.as_str()).send().await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status();
                    let detail = ApiError::read(response).await;
                    if last || !detail.is_retryable(status) {
                        return Err(detail.into_error(action, status));
                    }
                }
                Err(e) if !last && (e.is_timeout() || e.is_connect()) => {}
                Err(e) => {
                    return Err(anyhow!(e.without_url()))
                        .with_context(|| format!("cannot reach Google Drive ({action})"));
                }
            }
            tokio::time::sleep(delay + jitter(delay)).await;
            delay *= 2;
        }
        unreachable!("the final attempt always returns")
    }
}

impl Store for DriveClient {
    async fn list(&self) -> Result<Vec<DriveFile>> {
        self.query_files("trashed = false").await
    }

    async fn find(&self, drive_name: &str) -> Result<Vec<DriveFile>> {
        let q = format!(
            "name = '{}' and trashed = false",
            escape_query_literal(drive_name)
        );
        self.query_files(&q).await
    }

    async fn create(&self, drive_name: &str, envelope: &[u8]) -> Result<DriveFile> {
        let metadata = serde_json::json!({ "name": drive_name, "parents": ["appDataFolder"] });
        let (content_type, body) = multipart_related(&metadata.to_string(), envelope)?;
        let url = format!("{}/files", self.upload_base);
        self.send("upload", || {
            self.http
                .post(&url)
                .query(&[("uploadType", "multipart"), ("fields", FILE_FIELDS)])
                .header(reqwest::header::CONTENT_TYPE, &content_type)
                .body(body.clone())
        })
        .await?
        .json()
        .await
        .context("unexpected response from Google Drive (upload)")
    }

    async fn update(&self, file_id: &str, envelope: &[u8]) -> Result<DriveFile> {
        let url = format!("{}/files/{}", self.upload_base, checked_id(file_id)?);
        self.send("update", || {
            self.http
                .patch(&url)
                .query(&[("uploadType", "media"), ("fields", FILE_FIELDS)])
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(envelope.to_vec())
        })
        .await?
        .json()
        .await
        .context("unexpected response from Google Drive (update)")
    }

    async fn download(&self, file_id: &str) -> Result<Vec<u8>> {
        let url = format!("{}/files/{}", self.meta_base, checked_id(file_id)?);
        let mut response = self
            .send("download", || {
                self.http.get(&url).query(&[("alt", "media")])
            })
            .await?;
        // Enforced on the bytes actually received, not on Content-Length (see D15).
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("download from Google Drive was interrupted")?
        {
            if body.len() + chunk.len() > MAX_DOWNLOAD {
                bail!(
                    "vault file is larger than {} KiB; refusing to download it",
                    MAX_DOWNLOAD / 1024
                );
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn delete(&self, file_id: &str) -> Result<()> {
        let url = format!("{}/files/{}", self.meta_base, checked_id(file_id)?);
        self.send("delete", || self.http.delete(&url)).await?;
        Ok(())
    }
}

/// Escapes a string for use inside a single-quoted Drive query literal:
/// backslash first, then the single quote.
pub fn escape_query_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Drive file IDs are URL-safe tokens; reject anything else before building a URL path.
fn checked_id(file_id: &str) -> Result<&str> {
    if !file_id.is_empty()
        && file_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(file_id)
    } else {
        bail!("invalid Google Drive file ID")
    }
}

/// Builds a `multipart/related` body (metadata JSON part + binary media part), as Drive's
/// `uploadType=multipart` requires. Returns the `Content-Type` header value and the body.
fn multipart_related(metadata_json: &str, media: &[u8]) -> Result<(String, Vec<u8>)> {
    let boundary = loop {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| anyhow!("the operating system's random number generator failed"))?;
        let boundary: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let boundary = format!("pem-vault-{boundary}");
        let needle = boundary.as_bytes();
        if !media.windows(needle.len()).any(|w| w == needle) {
            break boundary;
        }
    };
    let mut body = Vec::with_capacity(media.len() + metadata_json.len() + 256);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata_json}\r\n\
             --{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(media);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok((format!("multipart/related; boundary={boundary}"), body))
}

fn jitter(delay: Duration) -> Duration {
    let max = delay.as_millis().max(1) as u32 / 2 + 1;
    Duration::from_millis(u64::from(getrandom::u32().unwrap_or(0) % max))
}

/// The parts of a Google API error body pem-vault acts on.
#[derive(Default)]
struct ApiError {
    reason: String,
    message: String,
}

impl ApiError {
    async fn read(response: Response) -> Self {
        #[derive(Deserialize)]
        struct Body {
            error: Detail,
        }
        #[derive(Deserialize)]
        struct Detail {
            #[serde(default)]
            message: String,
            #[serde(default)]
            errors: Vec<Item>,
        }
        #[derive(Deserialize)]
        struct Item {
            #[serde(default)]
            reason: String,
        }
        match response.json::<Body>().await {
            Ok(body) => Self {
                reason: body
                    .error
                    .errors
                    .into_iter()
                    .next()
                    .map(|i| i.reason)
                    .unwrap_or_default(),
                message: body.error.message,
            },
            Err(_) => Self::default(),
        }
    }

    fn is_rate_limit(&self) -> bool {
        matches!(
            self.reason.as_str(),
            "rateLimitExceeded" | "userRateLimitExceeded"
        )
    }

    fn is_retryable(&self, status: StatusCode) -> bool {
        status == StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
            || (status == StatusCode::FORBIDDEN && self.is_rate_limit())
    }

    fn into_error(self, action: &str, status: StatusCode) -> anyhow::Error {
        let api_disabled = self.reason == "accessNotConfigured"
            || self.message.contains("has not been used in project")
            || self.message.contains("is disabled");
        match status {
            StatusCode::UNAUTHORIZED => anyhow!(
                "Google Drive rejected the access token ({action}); run `pem-vault auth` to sign in again"
            ),
            StatusCode::FORBIDDEN if api_disabled => anyhow!(
                "the Google Drive API is not enabled for your Cloud project (README → Google Cloud setup, step 2)"
            ),
            StatusCode::FORBIDDEN if self.is_rate_limit() => {
                anyhow!("Google Drive rate limit exceeded ({action}); try again in a minute")
            }
            StatusCode::FORBIDDEN => anyhow!(
                "Google Drive denied access ({action}); run `pem-vault auth` and allow the Drive app-data permission"
            ),
            StatusCode::NOT_FOUND => {
                anyhow!(
                    "the file was not found in the Drive vault ({action}); it may have been deleted"
                )
            }
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow!("Google Drive rate limit exceeded ({action}); try again in a minute")
            }
            s if s.is_server_error() => {
                anyhow!("Google Drive is having problems (HTTP {s}, {action}); try again later")
            }
            s => {
                let message: String = self.message.chars().take(200).collect();
                anyhow!("Google Drive request failed (HTTP {s}, {action}): {message}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{
        body_bytes, header, method, path, query_param, query_param_is_missing,
    };
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    async fn server() -> (MockServer, DriveClient) {
        let server = MockServer::start().await;
        let client = DriveClient::for_mock(&server.uri());
        (server, client)
    }

    fn file_json(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "name": name, "size": "134", "modifiedTime": "2026-09-30T06:24:05.000Z" })
    }

    fn api_error(code: u16, reason: &str, message: &str) -> ResponseTemplate {
        ResponseTemplate::new(code).set_body_json(serde_json::json!({
            "error": { "code": code, "message": message, "errors": [{ "reason": reason }] }
        }))
    }

    // ---- Query escaping (P6.2) ------------------------------------------------------------

    #[test]
    fn escapes_backslash_then_quote() {
        assert_eq!(escape_query_literal("plain.pem.enc"), "plain.pem.enc");
        assert_eq!(escape_query_literal("it's"), "it\\'s");
        assert_eq!(escape_query_literal("a\\b"), "a\\\\b");
        // A trailing backslash must not be able to escape the closing quote.
        assert_eq!(
            escape_query_literal("x\\' or name != '"),
            "x\\\\\\' or name != \\'"
        );
    }

    #[test]
    fn file_ids_are_checked() {
        assert!(checked_id("1aBcDe-Fg_H").is_ok());
        for bad in ["", "../x", "a/b", "a?b", "a b", "a%2F"] {
            assert!(checked_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn size_is_parsed_from_string() {
        let f: DriveFile = serde_json::from_value(file_json("i", "n")).unwrap();
        assert_eq!(f.size(), Some(134));
    }

    // ---- list / find (P6.3, P6.4) ------------------------------------------------------------

    #[tokio::test]
    async fn list_follows_pagination_within_app_data_folder() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files"))
            .and(header("authorization", "Bearer test-token"))
            .and(query_param("spaces", "appDataFolder"))
            .and(query_param("q", "trashed = false"))
            .and(query_param("fields", LIST_FIELDS))
            .and(query_param_is_missing("pageToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "nextPageToken": "page-2", "files": [file_json("1", "a.pem.enc")]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files"))
            .and(query_param("spaces", "appDataFolder"))
            .and(query_param("pageToken", "page-2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "files": [file_json("2", "b.pem.enc")] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let names: Vec<_> = client
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(names, ["a.pem.enc", "b.pem.enc"]);
    }

    #[tokio::test]
    async fn find_uses_escaped_name_query_and_returns_all_matches() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files"))
            .and(query_param("spaces", "appDataFolder"))
            .and(query_param("q", "name = 'it\\'s.enc' and trashed = false"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "files": [file_json("1", "it's.enc"), file_json("2", "it's.enc")]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let found = client.find("it's.enc").await.unwrap();
        assert_eq!(found.len(), 2, "duplicates must be surfaced, not collapsed");
    }

    #[tokio::test]
    async fn find_with_no_match_is_empty() {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "files": [] })),
            )
            .mount(&server)
            .await;
        assert!(client.find("missing.pem.enc").await.unwrap().is_empty());
    }

    // ---- create (P6.5) -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_sends_multipart_related_with_metadata_and_media() {
        let (server, client) = server().await;
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .and(header("authorization", "Bearer test-token"))
            .and(query_param("uploadType", "multipart"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(file_json("new-id", "k.pem.enc")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let envelope = b"PEMVAULT\x01binary\r\n--not-a-boundary\x00\xff";
        let created = client.create("k.pem.enc", envelope).await.unwrap();
        assert_eq!(created.id, "new-id");

        let request: Request = server.received_requests().await.unwrap().remove(0);
        let content_type = request.headers["content-type"].to_str().unwrap();
        let boundary = content_type
            .strip_prefix("multipart/related; boundary=")
            .expect(content_type);
        let mut expected = format!(
            "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n\
             {{\"name\":\"k.pem.enc\",\"parents\":[\"appDataFolder\"]}}\r\n\
             --{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
        expected.extend_from_slice(envelope);
        expected.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        assert_eq!(request.body, expected);
    }

    #[test]
    fn multipart_boundary_is_random_and_absent_from_media() {
        let (a, _) = multipart_related("{}", b"x").unwrap();
        let (b, body) = multipart_related("{}", b"x").unwrap();
        assert_ne!(a, b);
        let boundary = b.strip_prefix("multipart/related; boundary=").unwrap();
        // Boundary appears exactly 3 times: two part delimiters and the closing delimiter.
        let count = body
            .windows(boundary.len())
            .filter(|w| *w == boundary.as_bytes())
            .count();
        assert_eq!(count, 3);
    }

    // ---- update / download / delete (P6.6–P6.8) ------------------------------------------------

    #[tokio::test]
    async fn update_patches_media_in_place() {
        let (server, client) = server().await;
        Mock::given(method("PATCH"))
            .and(path("/upload/drive/v3/files/abc-123"))
            .and(query_param("uploadType", "media"))
            .and(header("content-type", "application/octet-stream"))
            .and(body_bytes(b"new envelope".to_vec()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(file_json("abc-123", "k.pem.enc")),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client.update("abc-123", b"new envelope").await.unwrap().id,
            "abc-123"
        );
    }

    #[tokio::test]
    async fn download_returns_media_bytes() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files/abc-123"))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"\x00envelope\xff".to_vec()))
            .mount(&server)
            .await;
        assert_eq!(
            client.download("abc-123").await.unwrap(),
            b"\x00envelope\xff"
        );
    }

    #[tokio::test]
    async fn download_rejects_oversized_file() {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; MAX_DOWNLOAD + 1]))
            .mount(&server)
            .await;
        let err = client.download("big").await.unwrap_err().to_string();
        assert!(err.contains("larger than"), "{err}");
    }

    #[tokio::test]
    async fn delete_sends_delete() {
        let (server, client) = server().await;
        Mock::given(method("DELETE"))
            .and(path("/drive/v3/files/abc-123"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        client.delete("abc-123").await.unwrap();
    }

    #[tokio::test]
    async fn invalid_file_id_is_rejected_before_any_request() {
        let (server, client) = server().await;
        assert!(client.download("../../x").await.is_err());
        assert!(client.update("a/b", b"x").await.is_err());
        assert!(client.delete("").await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    // ---- Errors & retries (P6.9) ----------------------------------------------------------------

    async fn list_error(response: ResponseTemplate) -> String {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(response)
            .mount(&server)
            .await;
        client.list().await.unwrap_err().to_string()
    }

    #[tokio::test]
    async fn error_messages_are_actionable() {
        let cases = [
            (
                api_error(401, "authError", "Invalid Credentials"),
                "pem-vault auth",
            ),
            (
                api_error(
                    403,
                    "accessNotConfigured",
                    "Drive API has not been used in project 1",
                ),
                "not enabled",
            ),
            (
                api_error(403, "insufficientPermissions", "Insufficient Permission"),
                "app-data permission",
            ),
            (api_error(404, "notFound", "File not found: x"), "not found"),
            (api_error(400, "invalid", "Invalid Value"), "Invalid Value"),
        ];
        for (response, expected) in cases {
            let err = list_error(response).await;
            assert!(err.contains(expected), "expected {expected:?} in {err:?}");
        }
    }

    #[tokio::test]
    async fn retries_rate_limit_then_succeeds() {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "files": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(client.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn retries_403_rate_limit_reason() {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(api_error(403, "userRateLimitExceeded", "Rate limit"))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "files": [] })),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.list().await.unwrap();
    }

    #[tokio::test]
    async fn gives_up_after_three_server_errors() {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(ResponseTemplate::new(503))
            .expect(3)
            .mount(&server)
            .await;
        let err = client.list().await.unwrap_err().to_string();
        assert!(err.contains("try again later"), "{err}");
    }

    #[tokio::test]
    async fn client_errors_are_not_retried() {
        let (server, client) = server().await;
        Mock::given(path("/drive/v3/files"))
            .respond_with(api_error(400, "invalid", "Invalid Value"))
            .expect(1)
            .mount(&server)
            .await;
        assert!(client.list().await.is_err());
    }

    #[tokio::test]
    async fn uploads_are_retried_with_the_full_body() {
        let (server, client) = server().await;
        Mock::given(path("/upload/drive/v3/files/abc"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(path("/upload/drive/v3/files/abc"))
            .and(body_bytes(b"envelope".to_vec()))
            .respond_with(ResponseTemplate::new(200).set_body_json(file_json("abc", "k.enc")))
            .expect(1)
            .mount(&server)
            .await;
        client.update("abc", b"envelope").await.unwrap();
    }
}
