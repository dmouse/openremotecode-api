# ADR 0005: Account-owned connector revocation and naming

Status: accepted.

## Decision

Add `POST /v1/connectors/{connectorID}/revoke` using an account access token.
The authenticated principal supplies the account ID; the caller supplies only
the connector ID. The service rechecks account authorization and connector
ownership in the revocation operation. A device does not need a pairing key to
remove its account's connector, so lost-device recovery remains possible.

Revocation sets the existing `revoked_at` field and appends `connector.revoked`
in one transaction. It retains the row and credential hash for idempotent retries
and audit history. Active inventory excludes revoked rows. Existing ticket and
relay validation rejects them: outstanding/new admission is denied and an active
connector socket is closed by the existing bounded revalidation loop. Revocation
applies to all devices using this connector; local OpenCode chats are unaffected.

Mobile presents an explicit Delete and revoke confirmation describing that scope.
It waits for server acknowledgement before deleting its local public trust pin
and removing the row. Failure retains the row for retry. A local secure-store
failure after server success explicitly reports that revocation already happened;
repeating the request is safe. The mobile private identity and other connector
bindings remain intact. No chat/control protocol capabilities are added.

## Threat analysis

- Foreign and missing IDs both return 404. Unauthorized callers cannot discover
  or revoke another account's connector. IDs are never accepted as proof of ownership.
- Valid account tokens can revoke their connectors without plugin credentials;
  this is an account administration operation, not authorization to decrypt chats.
- Native requests and allowlisted browser origins are supported; cross-site and
  disallowed origins are rejected. Access tokens, rate limits, and no-store headers
  follow the existing account API behavior.
- Duplicate requests append one audit event. Failed audit writes roll back the
  revocation. No secrets, names, conversation content, or raw request errors enter
  new audit/log fields.
- Network timeouts have uncertain outcomes; the app does not claim a local-only
  delete revoked access. Lost responses can be retried against the retained row.

## Validation

Service tests cover ownership, unknown IDs, disabled accounts, expired connector
credentials, repeat revocation, audit rollback, and revoked admission. HTTP tests
cover account/connector token separation, origin policy, response codes, and cache
headers. Native Android tests pair a simulated connector, revoke through the mobile
repository, verify inventory/pin removal, observe the existing socket close, and
verify new tickets fail. Flutter tests cover confirmation, cancellation, duplicate
actions, delayed responses, and network failure/retry.

The plugin's local authorization display is separate from server authority. Its
existing local revoke action can clear the retained local authorization before a
fresh pairing. Server revocation never attempts to edit the user's local files.

## Naming

`POST /v1/connectors/{connectorID}/rename` uses the same account ownership and
origin checks, with a single `name` field. Names are trimmed and validated using
the existing 64-byte UTF-8 limit. The transaction locks the connector row, rejects
foreign/missing/revoked records, and saves the name with a `connector.renamed`
audit event containing only IDs. Repeating the same name is idempotent. No
identity, credential, trust binding, creation time, or conversation is modified.
A concurrent revoke and rename serialize through the existing row lock.

Mobile exposes Rename and Delete through a three-dot menu. Names update after
server acknowledgement; failure retains the prior display and offers refresh or
retry for an uncertain response. Renaming, deletion, and pairing cannot overlap
from the UI. Service/HTTP tests cover owner isolation, input validation, audit
rollback, unchanged admission, and missing/revoked IDs. Native tests verify the
name through subsequent inventory reads and repository recreation.
