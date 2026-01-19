# Octo Identity Services - Project Overview

## Purpose
Octo Identity Services is an OpenID Connect/OAuth2 identity and access management service built on Duende IdentityServer. It serves as a core component of the Octo Data Mesh platform, providing:

- **Multi-tenant authentication**: Support for multiple tenants with isolated authentication contexts
- **User management**: Complete user lifecycle management (creation, updates, roles, permissions)
- **Dynamic authentication provider configuration**: Pluggable authentication providers (Google, Microsoft, Azure Entra ID, LDAP, AD, Facebook)
- **Identity and access management**: OAuth2/OpenID Connect flows for securing APIs and applications

## Key Features
- OAuth2/OpenID Connect compliant authentication
- Multi-tenant support with tenant-specific configurations
- Dynamic authentication provider registration
- MongoDB-backed persistence
- REST API for system management (users, roles, clients, resources, scopes)
- Email notifications for user interactions (welcome, password reset)
- Distributed event handling for cross-service communication

## Repository
- **URL**: https://github.com/meshmakers/octo-identity-services
- **Company**: https://www.meshmakers.io
- **License**: See LICENSE file in repository root

## Target Environment
- **Platform**: Cross-platform (.NET 9.0)
- **Database**: MongoDB
- **Deployment**: Docker containers
- **Development OS**: macOS (Darwin), Windows, Linux supported
