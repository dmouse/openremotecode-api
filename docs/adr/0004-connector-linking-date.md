# Connector linking date in OpenCode

## Decision

Expose the connector's persisted `CreatedAt` as `linkedAt` in completed pairing poll responses. It represents the original successful account pairing that created this connector identity, not a process start, refresh, filesystem modification, or inferred credential issuance date. Retried pairing polls return the same timestamp. No database migration is needed.

New plugin authorizations save this optional timestamp in the existing permission-restricted version 1 record. Existing records and older pairing responses remain valid without it. The token details screen displays the exact date with timezone and an age in minutes, hours, or days; ages below a minute and slight future clock skew display “just now.” Reopening details recalculates the age.

`GET /v1/connectors/self` lets an existing connector retrieve only its ID and original linking date. The server derives the target from the hashed bearer credential and validates account state, credential expiry, and revocation. Requests cannot select another connector or account. The endpoint rejects browser Origin and cross-site requests, is rate limited, and returns `Cache-Control: no-store`.

The TUI fetches missing dates only when opening an older token's details. Back, revocation, closing the dialog, and disposal cancel the lookup. Results must match the current connector and authorization. The lookup never rewrites stored authorization, so a delayed metadata response cannot restore a revoked credential. If metadata is unavailable, invalid, or mismatched, the date remains unknown and Back/Revoke remain usable. Only new pairings persist the timestamp; older authorizations fetch it again when reopened.

## Threat analysis and observability

Link age is informational and does not participate in trust or expiration decisions. The narrow metadata response omits account details, credentials, hashes, and identity keys. The credential is sent only in the authorization header to the stored validated service origin; redirects are rejected. This read operation creates no trust, authorization, or audit mutation. Existing HTTP error handling logs only a fixed operation category; remote error text is not displayed in the modal. Server-supplied metadata is not end-to-end authenticated and cannot be treated as proof of trust.

## Verification

Tests cover repeated pairing timestamps, parsing and persistence, legacy records, invalid dates, relative-age boundaries, account isolation, revoked/expired credentials, the HTTP response shape, and legacy lookup cancellation. PostgreSQL integration checks the pairing result and authenticated metadata endpoint against the persisted date. The native OpenTUI test separately verifies the green Active indicator on selected-row text.
