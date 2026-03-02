# System API Reference

## Overview

The System API provides RESTful endpoints for managing identity resources including users, clients, roles, API resources, and identity providers.

**Base Path:** `system/v{version:apiVersion}` (e.g., `system/v1`)

**API Version:** 1.0

**Authentication:** Bearer Token (OIDC Authorization Header)

## Authorization Policies

### IdentityApiReadOnlyPolicy

- **Scopes Required:** `IdentityApiFullAccess` OR `IdentityApiReadOnly`
- **Applied To:** All GET endpoints

### IdentityApiReadWritePolicy

- **Scopes Required:** `IdentityApiFullAccess` only
- **Applied To:** All POST, PUT, DELETE endpoints (except Setup)

## Endpoints

### Users (`/system/v1/users`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/users` | ReadOnly | Get all users |
| GET | `/users/GetPaged` | ReadOnly | Get paginated users |
| GET | `/users/{userName}` | ReadOnly | Get user by name, email, or ID |
| GET | `/users/{userName}/roles` | ReadOnly | Get user's roles |
| POST | `/users` | ReadWrite | Create new user |
| POST | `/users/ResetPassword` | ReadWrite | Reset user password |
| PUT | `/users/{userName}` | ReadWrite | Update user |
| PUT | `/users/{userName}/roles` | ReadWrite | Replace all user roles |
| PUT | `/users/{userName}/roles/{roleName}` | ReadWrite | Add role to user |
| POST | `/users/{userName}/merge` | ReadWrite | Merge source user into target user |
| DELETE | `/users/{userName}` | ReadWrite | Delete user |
| DELETE | `/users/{userName}/roles/{roleName}` | ReadWrite | Remove role from user |

**Request/Response DTOs:**

```typescript
// RegisterUserDto (POST /users)
{
  "firstName": "string",
  "lastName": "string",
  "email": "string",
  "name": "string",           // Display name
  "password": "string",       // Required for creation
  "resetPasswordOnLogin": true
}

// UserDto (Response)
{
  "userId": "string",
  "firstName": "string",
  "lastName": "string",
  "email": "string",
  "name": "string",
  "resetPasswordOnLogin": true
}

// MergeUsersRequestDto (POST /users/{userName}/merge)
{
  "sourceUserName": "string"  // User whose external logins will be transferred
}
```

**Merge Users:**

Transfers all external logins (e.g., Google, Microsoft) from the source user to the target user, then deletes the source user. This is useful for consolidating duplicate accounts created by external identity providers.

- `{userName}` in the URL is the **target** user (kept after merge)
- `sourceUserName` in the body is the user whose logins are transferred and who is deleted
- Returns 404 if either user does not exist
- Returns 400 if attempting to merge a user into itself

### Clients (`/system/v1/clients`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/clients` | ReadOnly | Get all clients |
| GET | `/clients/GetPaged` | ReadOnly | Get paginated clients |
| GET | `/clients/{id}` | ReadOnly | Get client by ID |
| POST | `/clients` | ReadWrite | Create new client |
| PUT | `/clients/{id}` | ReadWrite | Update client |
| DELETE | `/clients/{id}` | ReadWrite | Delete client |

**Request/Response DTO:**

```typescript
// ClientDto
{
  "isEnabled": true,
  "clientId": "string",       // Unique identifier
  "clientSecret": "string",   // Optional
  "clientName": "string",
  "clientUri": "string",
  "allowedGrantTypes": ["authorization_code", "client_credentials"],
  "redirectUris": ["https://app.example.com/callback"],
  "postLogoutRedirectUris": ["https://app.example.com/logout"],
  "allowedCorsOrigins": ["https://app.example.com"],
  "allowedScopes": ["openid", "profile", "api"],
  "isOfflineAccessEnabled": true
}
```

### Roles (`/system/v1/roles`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/roles` | ReadOnly | Get all roles |
| GET | `/roles/GetPaged` | ReadOnly | Get paginated roles |
| GET | `/roles/names/{roleName}` | ReadOnly | Get role by name |
| POST | `/roles` | ReadWrite | Create role |
| PUT | `/roles/{roleName}` | ReadWrite | Update role |
| DELETE | `/roles/{roleName}` | ReadWrite | Delete role |

**Request/Response DTO:**

```typescript
// RoleDto
{
  "id": "string",
  "name": "string"
}
```

### API Resources (`/system/v1/apiResources`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiResources` | ReadOnly | Get all API resources |
| GET | `/apiResources/GetPaged` | ReadOnly | Get paginated resources |
| GET | `/apiResources/{name}` | ReadOnly | Get resource by name |
| POST | `/apiResources` | ReadWrite | Create resource |
| PUT | `/apiResources/{name}` | ReadWrite | Update resource |
| DELETE | `/apiResources/{name}` | ReadWrite | Delete resource |

**Request/Response DTO:**

```typescript
// ApiResourceDto
{
  "isEnabled": true,
  "name": "string",
  "displayName": "string",
  "description": "string",
  "showInDiscoveryDocument": true,
  "userClaims": ["sub", "name"],
  "requireResourceIndicator": false,
  "scopes": ["api.read", "api.write"],
  "allowedAccessTokenSigningAlgorithms": ["RS256"]
}
```

### API Scopes (`/system/v1/apiScopes`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiScopes` | ReadOnly | Get all scopes |
| GET | `/apiScopes/GetPaged` | ReadOnly | Get paginated scopes |
| GET | `/apiScopes/{name}` | ReadOnly | Get scope by name |
| POST | `/apiScopes` | ReadWrite | Create scope |
| PUT | `/apiScopes/{name}` | ReadWrite | Update scope |
| DELETE | `/apiScopes/{name}` | ReadWrite | Delete scope |

**Request/Response DTO:**

```typescript
// ApiScopeDto
{
  "isEnabled": true,
  "name": "string",
  "displayName": "string",
  "description": "string",
  "showInDiscoveryDocument": true,
  "userClaims": ["sub"],
  "isRequired": false,
  "isEmphasize": false
}
```

### API Secrets (`/system/v1/apiSecrets`)

#### Client Secrets

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiSecrets/client/{clientId}` | ReadOnly | Get client's secrets |
| GET | `/apiSecrets/client/{clientId}/{secretValue}` | ReadOnly | Get specific secret |
| POST | `/apiSecrets/client/{clientId}` | ReadWrite | Create client secret |
| PUT | `/apiSecrets/client/{clientId}` | ReadWrite | Update client secret |
| DELETE | `/apiSecrets/client/{clientId}/{secretValue}` | ReadWrite | Delete secret |

#### API Resource Secrets

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiSecrets/apiResource/{name}` | ReadOnly | Get resource's secrets |
| GET | `/apiSecrets/apiResource/{name}/{secretValue}` | ReadOnly | Get specific secret |
| POST | `/apiSecrets/apiResource/{name}` | ReadWrite | Create resource secret |
| PUT | `/apiSecrets/apiResource/{name}` | ReadWrite | Update resource secret |
| DELETE | `/apiSecrets/apiResource/{name}/{secretValue}` | ReadWrite | Delete secret |

**Request/Response DTO:**

```typescript
// ApiSecretDto
{
  "valueEncrypted": "string",   // SHA256 hash
  "valueClearText": "string",   // Only in creation response
  "expirationDate": "2025-12-31T00:00:00Z",
  "description": "string"
}
```

**Note:** Secret values are auto-generated GUIDs. The clear text is returned only once during creation.

### Identity Providers (`/system/v1/identityProviders`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/identityProviders` | ReadOnly | Get all providers |
| GET | `/identityProviders/{rtId}` | ReadOnly | Get provider by ID |
| POST | `/identityProviders` | ReadWrite | Add new provider |
| PUT | `/identityProviders/{rtId}` | ReadWrite | Replace provider |
| DELETE | `/identityProviders/{rtId}` | ReadWrite | Delete provider |

**Response Format:**

```typescript
// IdentityProvidersResult
{
  "identityProviders": [
    {
      "name": "string",
      "displayName": "string",
      "isEnabled": true,
      // Provider-specific fields...
    }
  ]
}
```

### Diagnostics (`/system/v1/diagnostics`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/diagnostics` | Authenticated | Get current user's diagnostics |
| POST | `/diagnostics/reconfigureLogLevel` | ReadWrite | Change log level |

**Log Level Configuration:**

```typescript
// Query parameters
?minLogLevel=Debug&maxLogLevel=Error&loggerName=Meshmakers
```

### Setup (`/system/v1/setup`) — System API (Bearer Auth)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| POST | `/setup` | Authenticated | Configure initial admin user |

**Note:** Only available when no users exist in the system. Requires Bearer token authentication (used by `octo-cli`).

**Request DTO:**

```typescript
// AdminUserDto
{
  "email": "admin@example.com",
  "password": "SecurePassword123!"
}
```

### Setup (`/{tenantId}/api/setup`) — SPA API (Anonymous)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/{tenantId}/api/setup/status` | Anonymous | Check if initial setup is required |
| POST | `/{tenantId}/api/setup/create-admin` | Anonymous | Create initial admin user |

**Note:** Both endpoints return `404 Not Found` when users already exist, making the controller effectively invisible after setup is complete. This is the browser-facing counterpart of the System API setup endpoint.

**GET /status Response:**

```typescript
// SetupStatusDto (200 if setup needed, 404 if users exist)
{
  "setupRequired": true
}
```

**POST /create-admin Request:**

```typescript
// SetupAdminRequestDto
{
  "email": "admin@example.com",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!"
}
```

**POST /create-admin Response:**

```typescript
// SetupResultDto
{
  "success": true,
  "errorMessage": null
}
```

### Tools (`/system/v1/tools`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/tools/generatePassword` | ReadOnly | Generate random password |

**Response:**

```typescript
// GeneratedPasswordDto
{
  "password": "***REMOVED-DEMO-PASSWORD-AB3837***"  // 16-character alphanumeric
}
```

## Pagination

### Request Parameters

```
GET /system/v1/users/GetPaged?skip=0&take=100
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | int | 0 | Number of items to skip |
| `take` | int | 100 | Number of items to return |
| `filter` | string | null | Optional filter expression |

### Response Headers

```
X-Pagination: {"totalCount":250,"skip":0,"take":100}
```

### Response Format

```typescript
// PagedResult<T>
{
  "list": [...],
  "totalCount": 250,
  "skip": 0,
  "take": 100
}
```

## Error Responses

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing/invalid token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 500 | Internal Server Error |

### Error DTOs

```typescript
// NotFoundErrorDto
{
  "message": "Resource not found",
  "resourceType": "User",
  "resourceId": "john.doe"
}

// OperationFailedErrorDto
{
  "message": "Operation failed",
  "code": "VALIDATION_ERROR",
  "description": "Email is required"
}

// InternalServerErrorDto
{
  "message": "An unexpected error occurred",
  "correlationId": "abc-123-def"
}
```

## Cache Invalidation

Write operations on certain resources trigger distributed events:

| Resource | Event |
|----------|-------|
| Clients | `CorsClientsUpdate` |
| API Resources | `CorsClientsUpdate` |
| API Scopes | `CorsClientsUpdate` |
| Identity Providers | `IdentityProviderUpdate` |

These events ensure cache consistency across multiple service instances.

## Example Requests

### Create User

```http
POST /system/v1/users HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

### Create OAuth Client

```http
POST /system/v1/clients HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "isEnabled": true,
  "clientId": "my-web-app",
  "clientName": "My Web Application",
  "allowedGrantTypes": ["authorization_code"],
  "redirectUris": ["https://myapp.com/callback"],
  "postLogoutRedirectUris": ["https://myapp.com"],
  "allowedScopes": ["openid", "profile", "email", "api"]
}
```

### Get Paginated Users

```http
GET /system/v1/users/GetPaged?skip=20&take=10 HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### Merge Users

```http
POST /system/v1/users/john.doe/merge HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "sourceUserName": "Google_john.doe@example.com"
}
```

### Add Role to User

```http
PUT /system/v1/users/john.doe/roles/Admin HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```
