---
name: drive-api
description: Reference for the Google Drive v3 REST calls and Google OAuth endpoints pem-vault uses (appDataFolder list/create/update/download/delete, multipart/related upload format, query escaping, loopback PKCE, token refresh/revoke, error handling). Use when implementing or debugging drive.rs or auth.rs.
---

# drive-api reference

All Drive calls send `Authorization: Bearer <access_token>`, and every file operation is limited to `appDataFolder`.

## OAuth (Desktop client, loopback + PKCE)

| Step | Request |
|---|---|
| Authorize | `GET https://accounts.google.com/o/oauth2/v2/auth` with `client_id`, `redirect_uri=http://127.0.0.1:<port>`, `response_type=code`, `scope=https://www.googleapis.com/auth/drive.appdata`, `code_challenge=<b64url(sha256(verifier))>`, `code_challenge_method=S256`, `state=<random>`, `access_type=offline`, `prompt=consent` |
| Callback | `GET /?state=…&code=…` or `/?error=access_denied&state=…` on the loopback port |
| Exchange | `POST https://oauth2.googleapis.com/token` (form): `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`, `client_id`, `client_secret` |
| Refresh | `POST https://oauth2.googleapis.com/token` (form): `grant_type=refresh_token`, `refresh_token`, `client_id`, `client_secret` |
| Revoke | `POST https://oauth2.googleapis.com/revoke` (form): `token=<refresh_token>` |

Notes:
- Desktop clients accept any loopback port; bind `127.0.0.1:0` and use the port you get.
- `refresh_token` is only returned with `access_type=offline`, and reliably only with `prompt=consent`. Treat its absence on exchange as an error.
- Refresh failure `{"error":"invalid_grant"}` means the token was revoked or expired (7 days if the app is still in *Testing*). The app is intentionally kept in *Testing*, so expect this regularly. Handle it with the inline re-auth prompt (backlog P5.4).
- Access tokens last about an hour. The CLI gets a new one per command; no caching is needed.

## Drive v3 endpoints

Base URLs (keep them injectable for wiremock):
- Metadata: `https://www.googleapis.com/drive/v3`
- Upload: `https://www.googleapis.com/upload/drive/v3`

### List / find
```
GET {meta}/files
  ?spaces=appDataFolder
  &q=name = 'prod.pem.enc' and trashed = false     (omit name clause for list)
  &fields=nextPageToken,files(id,name,size,modifiedTime)
  &pageSize=100
  &pageToken=<from previous response>
```
Follow `nextPageToken` until it's absent. `size` is returned as a **string**.

### Query escaping
Inside `q` string literals, escape backslash first and then the single quote: `\` → `\\`, `'` → `\'`. URL-encoding is done by `reqwest`'s `.query()`; never build the query string by hand.

### Create (multipart/related)
```
POST {upload}/files?uploadType=multipart&fields=id,name
Content-Type: multipart/related; boundary=<B>

--<B>
Content-Type: application/json; charset=UTF-8

{"name":"prod.pem.enc","parents":["appDataFolder"]}
--<B>
Content-Type: application/octet-stream

<envelope bytes>
--<B>--
```
- Use CRLF (`\r\n`) line endings. Generate a random boundary that doesn't occur in the body (random bytes, then check).
- Don't use `reqwest::multipart`, which produces `multipart/form-data`.

### Update content (same file ID)
```
PATCH {upload}/files/{fileId}?uploadType=media&fields=id,name
Content-Type: application/octet-stream

<envelope bytes>
```
Don't send `parents` on update; parents can't be changed that way.

### Download
```
GET {meta}/files/{fileId}?alt=media
```
Check `Content-Length` if it's present and cap the streamed size at 2 MiB.

### Delete
```
DELETE {meta}/files/{fileId}      → 204 No Content
```
Files in `appDataFolder` can't be trashed, so delete is permanent.

## Errors

The body shape is `{"error":{"code":403,"message":"…","errors":[{"reason":"…"}]}}`.

| Status | Typical reason | Handling |
|---|---|---|
| 400 | `invalid`, bad `q` | Bug; show the message |
| 401 | `authError` | Token invalid. Refresh once; if that fails, tell the user to run `pem-vault auth` |
| 403 | `insufficientPermissions` | Scope wrong or not granted. Re-run `auth` |
| 403 | `userRateLimitExceeded`, `rateLimitExceeded` | Retry with backoff |
| 403 | `accessNotConfigured` | Drive API not enabled for the project (README setup step 2) |
| 404 | `notFound` | The file ID is gone. For `find` results, treat it as "not found" |
| 429 / 5xx | | Exponential backoff (for example 0.5 s, 1 s, 2 s with jitter), max 3 attempts |

Never include the token-endpoint response body in error messages.

## Testing with wiremock

- Point `DriveClient` and the auth token URL at `MockServer::uri()`.
- Assert the query parameters (`spaces`, `q`, `fields`), the bearer header, the `multipart/related` content type and the body parts.
- Cover pagination (two pages), duplicate names, 401, 404 and 429-then-200.
