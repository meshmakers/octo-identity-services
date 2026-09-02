using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using OpenIddict.Server;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

/// <summary>
///     OpenIddict server configuration (AB#4989/AB#4990).
///     Endpoint paths, flows, token format and signing certificate deliberately keep the
///     pre-migration wire contract so all consumers (SPAs, backend services, adapters, octo-cli,
///     MCP clients) keep working unchanged — the golden baseline in
///     <c>tests/IdentityServices.IntegrationTests/GoldenFiles</c> is the regression gate.
/// </summary>
public static class OpenIddictConfiguration
{
    /// <summary>
    ///     Wires the OpenIddict server/core/validation stack into the host. The CK/MongoDB-backed
    ///     stores (application/scope/authorization/token, AB#4991) are registered by
    ///     <c>AddOctoIdentityPersistence</c>; this method owns protocol configuration only.
    /// </summary>
    public static void AddOctoOpenIddict(this WebApplicationBuilder builder)
    {
        // Bound copies for composition-time decisions (issuer, certs, DCR discovery entry).
        var identityOptions = new OctoIdentityServicesOptions
        {
            AutoMapperLicenseKey = string.Empty
        };
        builder.Configuration.GetSection("Identity").Bind(identityOptions);
        var systemConfiguration = new OctoSystemConfiguration();
        builder.Configuration.GetSection("System").Bind(systemConfiguration);
        var systemTenantId = systemConfiguration.SystemTenantId.Trim().ToLowerInvariant();

        builder.Services.AddOpenIddict()
            .AddCore(coreOptions =>
            {
                // Custom stores projecting the existing Rt* CK entities (AB#4991) — the data
                // stays in place, only the mapping layer changes.
                coreOptions.SetDefaultApplicationEntity<RtClient>();
                coreOptions.SetDefaultScopeEntity<RtApiScope>();
                coreOptions.SetDefaultAuthorizationEntity<RtOAuthAuthorization>();
                coreOptions.SetDefaultTokenEntity<RtOAuthToken>();
                coreOptions.ReplaceApplicationStore<RtClient, OpenIddictApplicationStore>();
                coreOptions.ReplaceScopeStore<RtApiScope, OpenIddictScopeStore>();
                coreOptions.ReplaceAuthorizationStore<RtOAuthAuthorization, OpenIddictAuthorizationStore>();
                coreOptions.ReplaceTokenStore<RtOAuthToken, OpenIddictTokenStore>();

                // Validates client secrets against the legacy stored hash format (Base64
                // SHA-256/512) so existing secrets keep working without rotation.
                coreOptions.ReplaceApplicationManager<RtClient, OctoApplicationManager>();

                // CRITICAL: OpenIddict's application/scope cache is process-wide while our
                // stores resolve entities per request tenant — caching would leak clients
                // and scopes across tenants (same ClientId, different tenant DBs).
                coreOptions.DisableEntityCaching();
            })
            .AddServer(serverOptions =>
            {
                // Endpoint paths pinned to the pre-migration layout — consumers cache the
                // discovery document and octo-common-services derives the JWKS path from it.
                serverOptions
                    .SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetIntrospectionEndpointUris("connect/introspect")
                    .SetRevocationEndpointUris("connect/revocation")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetEndSessionEndpointUris("connect/endsession")
                    .SetDeviceAuthorizationEndpointUris("connect/deviceauthorization")
                    // Fixed, tenant-free verification endpoint driven by the Angular device page
                    // (/{tenantId}/device) via XHR; OidcTenantResolutionMiddleware rewrites the
                    // verification_uri in the device authorization response to the SPA page.
                    .SetEndUserVerificationEndpointUris("connect/deviceverification")
                    .SetPushedAuthorizationEndpointUris("connect/par")
                    .SetJsonWebKeySetEndpointUris(".well-known/openid-configuration/jwks");

                serverOptions
                    .AllowAuthorizationCodeFlow()
                    .AllowClientCredentialsFlow()
                    .AllowRefreshTokenFlow()
                    .AllowDeviceAuthorizationFlow()
                    // RFC 8693 token exchange is a first-class flow since OpenIddict 7.0 and
                    // replaces the custom TenantExchangeGrantValidator (AB#4992).
                    .AllowTokenExchangeFlow()
                    // Delegation / on-behalf-of (AB#5026): a service-account client presents a
                    // user's access token and receives a token on the USER's sub with
                    // role = SA roles ∩ user roles and act = the service account. Own URN,
                    // deliberately NOT the token-exchange one — a shared URN would also share the
                    // per-client opt-in (see DelegationConstants.OnBehalfOfGrantType).
                    .AllowCustomFlow(Services.DelegationConstants.OnBehalfOfGrantType);

                // Our resource services validate plain signed JWTs (RS256) — OpenIddict
                // encrypts access tokens (JWE) by default, which would break every consumer.
                serverOptions.DisableAccessTokenEncryption();

                serverOptions.SetIssuer(new Uri(identityOptions.AuthorityUrl.EnsureEndsWith("/")));

                if (builder.Environment.IsDevelopment())
                {
                    serverOptions
                        .AddDevelopmentSigningCertificate()
                        .AddDevelopmentEncryptionCertificate();
                }
                else
                {
                    // Same static PKCS#12 certificate the pre-migration server signed with: the
                    // JWKS stays identical, so access tokens issued before the cutover keep
                    // validating.
                    var certificate = SigningCertificateLoader.TryLoad(identityOptions)
                                      ?? throw new InvalidOperationException(
                                          $"Token signing certificate not found at '{identityOptions.KeyFilePath}' " +
                                          "(Identity:KeyFilePath / OCTO_IDENTITY__KeyFilePath).");
                    serverOptions.AddSigningCertificate(certificate);

                    // Encryption credential for OpenIddict-internal token payloads
                    // (authorization codes, device codes, refresh tokens — never access
                    // tokens, see DisableAccessTokenEncryption above). Reusing the signing
                    // certificate keeps the secret chain unchanged; these payloads are only
                    // ever produced and consumed by this service.
                    serverOptions.AddEncryptionCertificate(certificate);
                }

                // Pre-migration access token shape: array scope claim, no sub on
                // client_credentials, no oi_* private claims, no per-token DB entry (AB#4992).
                serverOptions.AddEventHandler(OctoAccessTokenShapeHandler.Descriptor);

                // Device flow: render the verification result as the JSON DTO the SPA expects.
                serverOptions.AddEventHandler(OctoDeviceVerificationResponseHandler.Descriptor);

                // Existing public clients (RequireClientSecret = false), e.g. octo-cli and
                // adapters, send a client_secret anyway — ignore it instead of rejecting with
                // invalid_client, as the pre-migration server did.
                serverOptions.AddEventHandler(OctoPublicClientSecretHandler.Descriptor);

                // OIDC session management: session_state on authorize responses +
                // check_session_iframe discovery entry (served by CheckSessionController).
                serverOptions.AddEventHandler(OctoSessionStateHandler.Descriptor);

                // RFC 8693 cross-tenant exchange: swap the built-in authorized-party check for a
                // variant that skips ONLY the token-exchange grant — platform access tokens carry
                // no presenter claims and API-resource audiences, so the built-in would reject
                // every exchange before TenantExchangeProcessor (the actual gatekeeper) runs.
                serverOptions.RemoveEventHandler(
                    OpenIddictServerHandlers.Exchange.ValidateAuthorizedParty.Descriptor);
                serverOptions.AddEventHandler(OctoTokenExchangeAuthorizedPartyHandler.Descriptor);
                var checkSessionEndpoint =
                    identityOptions.AuthorityUrl.EnsureEndsWith("/") + "connect/checksession";
                serverOptions.AddEventHandler<OpenIddictServerEvents.ApplyConfigurationResponseContext>(
                    handlerBuilder => handlerBuilder.UseInlineHandler(context =>
                    {
                        context.Response["check_session_iframe"] = checkSessionEndpoint;
                        return default;
                    }));

                // Pre-migration wire format (pinned by the golden baseline tests): the device
                // authorization response always carries the polling interval (5s); OpenIddict
                // omits it (RFC 8628 defaults to 5 when absent).
                serverOptions.AddEventHandler<OpenIddictServerEvents.ApplyDeviceAuthorizationResponseContext>(
                    handlerBuilder => handlerBuilder.UseInlineHandler(context =>
                    {
                        if (string.IsNullOrEmpty(context.Response.Error) &&
                            context.Response["interval"] is null)
                        {
                            context.Response["interval"] = 5;
                        }

                        return default;
                    }));

                // Pre-migration wire format (pinned by the golden baseline tests): the token
                // response always echoes the granted scopes. OpenIddict omits the scope member
                // when granted == requested (RFC 6749 makes it optional), so absence here means
                // the requested scopes were granted verbatim.
                serverOptions.AddEventHandler<OpenIddictServerEvents.ApplyTokenResponseContext>(
                    handlerBuilder => handlerBuilder.UseInlineHandler(context =>
                    {
                        if (string.IsNullOrEmpty(context.Response.Error) &&
                            !string.IsNullOrEmpty(context.Response.AccessToken) &&
                            string.IsNullOrEmpty((string?)context.Response.Scope) &&
                            !string.IsNullOrEmpty(context.Request?.Scope))
                        {
                            context.Response.Scope = context.Request.Scope;
                        }

                        return default;
                    }));

                // RFC 7591 DCR: advertise the hand-rolled /connect/register endpoint in the
                // discovery document when DCR is enabled (AB#4993 — OpenIddict has no built-in
                // hook for custom discovery entries, hence the inline handler).
                if (identityOptions.DynamicClientRegistration.Enabled)
                {
                    var registrationEndpoint =
                        identityOptions.AuthorityUrl.EnsureEndsWith("/") + "connect/register";
                    serverOptions.AddEventHandler<OpenIddictServerEvents.ApplyConfigurationResponseContext>(
                        handlerBuilder => handlerBuilder.UseInlineHandler(context =>
                        {
                            context.Response["registration_endpoint"] = registrationEndpoint;
                            return default;
                        }));
                }

                var aspNetCoreBuilder = serverOptions.UseAspNetCore()
                    // The Angular login SPA drives interaction through our API controllers;
                    // passthrough gives the Token/Authorize/EndSession/Verification controllers
                    // (AB#4992/AB#4995) control over principals, login, consent and
                    // tenant-scoped redirects.
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableEndUserVerificationEndpointPassthrough();

                if (builder.Environment.IsDevelopment())
                {
                    aspNetCoreBuilder.DisableTransportSecurityRequirement();
                }
            })
            .AddValidation(validationOptions =>
            {
                // Local validation for the userinfo endpoint and any OpenIddict-protected
                // endpoints; resource APIs keep their own JwtBearer validation.
                validationOptions.UseLocalServer();
                validationOptions.UseAspNetCore();
            });
    }
}
