using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

/// <summary>
///     OpenIddict server configuration replacing Duende IdentityServer (AB#4989/AB#4990).
///     Endpoint paths, flows, token format and signing certificate deliberately mirror the
///     Duende setup so all consumers (SPAs, backend services, adapters, octo-cli, MCP clients)
///     keep working unchanged — the golden baseline in
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

                // Duende-hash-compatible client secret validation (existing secrets keep working).
                coreOptions.ReplaceApplicationManager(typeof(OctoApplicationManager));

                // CRITICAL: OpenIddict's application/scope cache is process-wide while our
                // stores resolve entities per request tenant — caching would leak clients
                // and scopes across tenants (same ClientId, different tenant DBs).
                coreOptions.DisableEntityCaching();
            })
            .AddServer(serverOptions =>
            {
                // Endpoint paths pinned to the Duende layout — consumers cache the discovery
                // document and octo-common-services derives the JWKS path from it.
                serverOptions
                    .SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetIntrospectionEndpointUris("connect/introspect")
                    .SetRevocationEndpointUris("connect/revocation")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetEndSessionEndpointUris("connect/endsession")
                    .SetDeviceAuthorizationEndpointUris("connect/deviceauthorization")
                    .SetEndUserVerificationEndpointUris($"{systemTenantId}/device")
                    .SetPushedAuthorizationEndpointUris("connect/par")
                    .SetJsonWebKeySetEndpointUris(".well-known/openid-configuration/jwks");

                serverOptions
                    .AllowAuthorizationCodeFlow()
                    .AllowClientCredentialsFlow()
                    .AllowRefreshTokenFlow()
                    .AllowDeviceAuthorizationFlow()
                    // RFC 8693 token exchange is a first-class flow since OpenIddict 7.0 and
                    // replaces the custom TenantExchangeGrantValidator (AB#4992).
                    .AllowTokenExchangeFlow();

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
                    // Same static PKCS#12 certificate Duende signed with: the JWKS stays
                    // identical, so access tokens issued before the cutover keep validating.
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

                var aspNetCoreBuilder = serverOptions.UseAspNetCore()
                    // The Angular login SPA drives interaction through our API controllers;
                    // passthrough gives the Authorize/EndSession/Verification controllers
                    // (AB#4995) control over login, consent and tenant-scoped redirects.
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
