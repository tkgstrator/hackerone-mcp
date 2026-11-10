# Researcher-token GraphQL comments

Fix the existing report_comment_prepare/submit/get tools to support personal
researcher credentials through https://hackerone.com/graphql. Preserve Hacker
REST reads and new-report submission. Do not fall back to Customer REST or cookies.

The verified HackerOne reference repository is
/Users/devonly/Developer/hackerone-graphql-reference-20261110 at
c0d2f908c46082dce1e1e1287d435962469efdee. Read config.yaml, README.md and
graphql/operations/AddCommentToHackerOneReport.graphql. It uses
Authorization: Bearer base64(username:api_key) and createActivityComment with
report_id (GraphQL global ID), message and internal=false. The canonical report
global ID observed live decodes to gid://hackerone/Report/<id>. Local generation
of that canonical global ID preserves preparation as an offline operation.

Use one fixed mutation and operationName. New previews retain its exact JSON bytes
with bound report ID and message; the existing single-attempt durable claim and
cancellation-safe receipt recording remain in force. The GraphQL origin is fixed
separately from the existing REST origin; test helpers may use local mock origins.
Base64 may be added as a direct dependency using an already locked crate version;
do not introduce custom encoding or additional dependencies.

A successful HTTP status alone is insufficient. Require no GraphQL errors,
was_successful=true, no mutation validation errors, and an ActivitiesComment
receipt with a canonical numeric activity ID and matching message. Requests always
set internal=false. The response field is nullable: explicit false confirms the
requested visibility, explicit null means visibility was not returned, and missing,
true or malformed values remain invalid. Persist optional visibility_confirmed
as true/false respectively; older receipts without this field remain readable.
Normalize that accepted receipt for the existing workflow. Never quote raw HTTP
or GraphQL error bodies, credentials, or encoded authorization in errors. Never
retry or follow redirects for a mutation, including HTTP 200 GraphQL errors.

New comment ledgers use schema_version=2. Existing schema-1 REST receipts remain
readable and immutable. Reject submission of any schema-1 preview with guidance
to prepare a new preview after inspecting the old outcome; do not reinterpret its
stored request as GraphQL. Decode both legacy and current exact payloads. Expose
the transport in previews/receipts where useful and update stale Customer API
descriptions. The MCP tool names and their input parameters stay the same.

The user explicitly requested this fix and the Rush comment. Main owns runtime
verification, deployment and the real send. The implementation worker must not
read credentials, perform live API writes, commit or deploy. Tests use mock HTTP.
Main will confirm complete report activities before a new authorized attempt,
preserving the earlier consumed REST receipt. The exact comment is:

The WAVE1 restriction is not limited to Goldie Seeking. In WAVE1 Rush, there is also a direction that is never selected for the initial enemy spawn.

Bump the local patch version to 0.6.1, followed by 0.6.2 for the live nullable-response
compatibility fix. This is a bounded transport correction using
the existing workflow, not a general GraphQL proxy or a new authentication system.
