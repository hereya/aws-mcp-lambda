# aws/mcp-lambda

Hereya deployment package that provisions a stateless MCP server as an AWS Lambda function behind API Gateway HTTP API.

## Features

- Lambda function (Node.js 22) with `POST /mcp` route
- Optional Cognito JWT authentication at API Gateway level
- Optional custom domain with Route53 + ACM certificate
- Secure secret handling via AWS Secrets Manager
- IAM policy attachment support

## Usage

```bash
hereya add aws/mcp-lambda
```

With parameters:

```bash
hereya add aws/mcp-lambda \
  -p "customDomain=mcp.example.com" \
  -p "cognitoUserPoolId=eu-west-1_XXXXX"
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `cognitoUserPoolId` | _(none)_ | Cognito User Pool ID. When set, creates a User Pool Client and JWT authorizer on the API route. |
| `customDomain` | _(none)_ | Custom domain name (e.g. `mcp.example.com`). Requires a Route53 hosted zone. |
| `customDomainZone` | _(auto)_ | Route53 hosted zone. Auto-derived from `customDomain` if not set. |
| `memorySize` | `256` | Lambda memory in MB. |
| `timeout` | `30` | Lambda timeout in seconds. |
| `handler` | `handler.handler` | Lambda handler entry point. |

## Environment Variable Handling

Environment variables from `hereyaProjectEnv` are processed in three ways:

- **Plain variables** — passed directly as Lambda environment variables.
- **Secret variables** (prefixed with `secret://`) — stored in AWS Secrets Manager. The Lambda receives the secret name as an env var and reads the actual value at runtime. The Lambda is granted `secretsmanager:GetSecretValue` permission.
- **IAM policy variables** (prefixed with `IAM_POLICY_` or `iamPolicy`) — parsed as JSON IAM policy documents and attached to the Lambda execution role.

## Outputs

| Output | Description |
|--------|-------------|
| `ServiceUrl` | The API endpoint URL (custom domain or API Gateway URL). |
| `UserPoolClientId` | Cognito User Pool Client ID (only when `cognitoUserPoolId` is set). |

## Requirements

The consuming project must have a `dist/` directory containing the built Lambda handler (e.g. via `esbuild` or similar bundler).
