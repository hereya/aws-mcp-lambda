# aws/mcp-lambda

Hereya deployment package that provisions a stateless MCP server as an AWS Lambda function behind API Gateway HTTP API.

## Features

- Lambda function (Node.js 22) with `POST /mcp` route
- Optional hereya OAuth authentication with org-based access control
- OAuth Protected Resource Metadata endpoint (`/.well-known/oauth-protected-resource`)
- Lambda authorizer for RS256 JWT validation via JWKS
- Optional custom domain with Route53 + ACM certificate
- Secure secret handling via AWS Secrets Manager
- IAM policy attachment support

## Usage

```bash
hereya add aws/mcp-lambda
```

With OAuth authentication (recommended):

```bash
hereya add aws/mcp-lambda \
  -p "customDomain=mcp.example.com" \
  -p "oauthServerUrl=https://cloud.hereya.io" \
  -p "organizationId=your-org-id"
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `oauthServerUrl` | _(none)_ | hereya-cloud OAuth server URL (e.g. `https://cloud.hereya.io`). When set with `organizationId`, enables OAuth JWT auth. |
| `organizationId` | _(none)_ | hereya organization ID this MCP server is bound to. Required with `oauthServerUrl`. |
| `customDomain` | _(none)_ | Custom domain name (e.g. `mcp.example.com`). Requires a Route53 hosted zone. |
| `customDomainZone` | _(auto)_ | Route53 hosted zone. Auto-derived from `customDomain` if not set. |
| `memorySize` | `256` | Lambda memory in MB. |
| `timeout` | `30` | Lambda timeout in seconds. |
| `handler` | `handler.handler` | Lambda handler entry point. |

## Authentication Flow

When `oauthServerUrl` and `organizationId` are set:

1. MCP client sends `POST /mcp` → receives 401 Unauthorized
2. MCP client fetches `GET /.well-known/oauth-protected-resource` → discovers the authorization server
3. MCP client follows standard OAuth 2.0 with PKCE via hereya-cloud
4. hereya-cloud issues RS256 JWT with org claims
5. MCP client sends `POST /mcp` with `Authorization: Bearer <jwt>`
6. Lambda authorizer validates JWT signature via JWKS and checks org access
7. User context (userId, orgId, orgRole) is passed to the Lambda via `event.requestContext.authorizer.lambda`

## Environment Variable Handling

Environment variables from `hereyaProjectEnv` are processed in three ways:

- **Plain variables** — passed directly as Lambda environment variables.
- **Secret variables** (prefixed with `secret://`) — stored in AWS Secrets Manager. The Lambda receives the secret name as an env var and reads the actual value at runtime. The Lambda is granted `secretsmanager:GetSecretValue` permission.
- **IAM policy variables** (prefixed with `IAM_POLICY_` or `iamPolicy`) — parsed as JSON IAM policy documents and attached to the Lambda execution role.

## Outputs

| Output | Description |
|--------|-------------|
| `ServiceUrl` | The API endpoint URL (custom domain or API Gateway URL). |

## Requirements

The consuming project must have a `dist/` directory containing the built Lambda handler (e.g. via `esbuild` or similar bundler).
