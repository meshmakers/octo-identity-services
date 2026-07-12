using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.DynamicClientRegistration;

/// <inheritdoc />
public sealed class DynamicClientRegistrationService(
    ISystemContext systemContext,
    IClientMirrorProvisioningService mirrorProvisioning,
    IOptions<OctoIdentityServicesOptions> options,
    ILogger<DynamicClientRegistrationService> logger)
    : IDynamicClientRegistrationService
{
    /// <summary>
    ///     Client-id prefix of all dynamically-registered clients. Public so the authorize-time
    ///     default-scope middleware can recognize DCR clients without a store lookup. Deliberately
    ///     product-neutral ("dcr" = Dynamic Client Registration): the feature is a generic identity
    ///     capability — MCP clients (Claude Code) are merely its first consumer.
    /// </summary>
    public const string ClientIdPrefix = "octo-dcr-";

    public async Task<DynamicClientRegistrationResult> RegisterAsync(
        DynamicClientRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        var dcrOptions = options.Value.DynamicClientRegistration;
        if (!dcrOptions.Enabled)
        {
            return Disabled();
        }

        // --- Gate (Phase 3 refines the config knobs; the structural rules live here) ------------
        var redirectUris = request.RedirectUris ?? [];
        if (redirectUris.Count == 0)
        {
            return Invalid("invalid_redirect_uri", "At least one redirect_uri is required.");
        }

        foreach (var uri in redirectUris)
        {
            if (!IsLoopbackHttp(uri))
            {
                return Invalid("invalid_redirect_uri",
                    $"redirect_uri '{uri}' is not an allowed loopback http URI (127.0.0.1 / [::1] / localhost).");
            }
        }

        if (!string.IsNullOrEmpty(request.TokenEndpointAuthMethod) &&
            !string.Equals(request.TokenEndpointAuthMethod, "none", StringComparison.Ordinal))
        {
            return Invalid("invalid_client_metadata",
                "Only public clients are supported (token_endpoint_auth_method must be 'none').");
        }

        if (request.GrantTypes is { Count: > 0 } &&
            request.GrantTypes.Any(g => g is not ("authorization_code" or "refresh_token")))
        {
            return Invalid("invalid_client_metadata",
                "Only the authorization_code (+ refresh_token) grant is supported.");
        }

        // --- Persist into the system tenant (mirrored to all tenants below) ---------------------
        var systemTenantId = systemContext.TenantId;
        var repository = await systemContext.TryFindTenantRepositoryAsync(systemTenantId);
        if (repository == null)
        {
            logger.LogError("DCR: system tenant repository '{TenantId}' could not be resolved", systemTenantId);
            return Invalid("temporarily_unavailable", "Registration is temporarily unavailable.");
        }

        var requestedSet = new HashSet<string>(redirectUris, StringComparer.Ordinal);

        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var existingClients = await repository.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.DynamicRegistration), FieldFilterOperator.Equals, true));

        var now = DateTime.UtcNow;
        var liveClients = existingClients.Items
            .Where(c => !c.DynamicRegistrationExpiresAt.HasValue || c.DynamicRegistrationExpiresAt.Value > now)
            .ToList();

        // Dedupe: an equivalent, non-expired client already exists → re-issue it (RFC 7591 permits
        // returning the existing registration; stops per-launch client accumulation).
        var duplicate = liveClients.FirstOrDefault(c => RedirectUriSet(c).SetEquals(requestedSet));
        if (duplicate != null)
        {
            await session.CommitTransactionAsync();
            logger.LogInformation("DCR: re-issued existing dynamic client '{ClientId}'", duplicate.ClientId);
            return new DynamicClientRegistrationResult(
                DynamicClientRegistrationOutcome.ReturnedExisting, BuildResponse(duplicate, dcrOptions), null);
        }

        if (liveClients.Count >= dcrOptions.MaxClientsPerTenant)
        {
            await session.CommitTransactionAsync();
            logger.LogWarning("DCR: per-tenant cap {Cap} reached; refusing registration", dcrOptions.MaxClientsPerTenant);
            return new DynamicClientRegistrationResult(DynamicClientRegistrationOutcome.CapExceeded, null,
                new DynamicClientRegistrationError
                {
                    Error = "access_denied",
                    ErrorDescription = "Dynamic client registration cap reached for this instance."
                });
        }

        var client = BuildClient(request, redirectUris, dcrOptions, now);
        await repository.InsertOneRtEntityAsync(session, client);
        await session.CommitTransactionAsync();

        // Mirror into every existing tenant so the client resolves wherever the user authenticates.
        // Best-effort: a mirror failure must not fail the registration — startup provisioning and the
        // backfill endpoint re-converge. New tenants pick it up via DefaultConfigurationCreatorService.
        try
        {
            await mirrorProvisioning.ProvisionForAllChildTenantsAsync(systemTenantId, client.ClientId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DCR: mirroring of dynamic client '{ClientId}' into child tenants failed", client.ClientId);
        }

        logger.LogInformation("DCR: registered dynamic client '{ClientId}' (expires {Expiry:o})",
            client.ClientId, client.DynamicRegistrationExpiresAt);
        return new DynamicClientRegistrationResult(
            DynamicClientRegistrationOutcome.Created, BuildResponse(client, dcrOptions), null);
    }

    private static RtClient BuildClient(DynamicClientRegistrationRequest request, List<string> redirectUris,
        DynamicClientRegistrationOptions dcrOptions, DateTime now)
    {
        var redirectList = new AttributeRecordValueList<RtClientUriEntryRecord>();
        foreach (var uri in redirectUris)
        {
            redirectList.Add(new RtClientUriEntryRecord { Uri = uri, Source = ClientUriSources.Dynamic });
        }

        return new RtClient
        {
            Enabled = true,
            ClientId = ClientIdPrefix + Guid.NewGuid().ToString("N"),
            ClientName = string.IsNullOrWhiteSpace(request.ClientName)
                ? "Dynamically registered MCP client"
                : request.ClientName,
            ProtocolType = "oidc",

            AllowedGrantTypes = new AttributeStringValueList(["authorization_code"]),
            RequirePkce = true,
            RequireClientSecret = false,
            AllowAccessTokensViaBrowser = false,
            AlwaysIncludeUserClaimsInIdToken = true,
            AccessTokenType = RtTokenTypeEnum.Jwt,
            RequireConsent = false,
            AllowOfflineAccess = true,

            RedirectUris = redirectList,
            // Scopes are server-fixed, never client-chosen.
            AllowedScopes = new AttributeStringValueList(dcrOptions.AllowedScopes.ToList()),

            // System-tenant client, mirrored into every tenant like the built-in MCP clients.
            AutoProvisionInChildTenants = true,
            DynamicRegistration = true,
            DynamicRegistrationExpiresAt = now.AddDays(dcrOptions.ClientTtlDays)
        };
    }

    private static DynamicClientRegistrationResponse BuildResponse(RtClient client,
        DynamicClientRegistrationOptions dcrOptions)
    {
        var issuedAt = client.DynamicRegistrationExpiresAt.HasValue
            ? new DateTimeOffset(
                    DateTime.SpecifyKind(client.DynamicRegistrationExpiresAt.Value.AddDays(-dcrOptions.ClientTtlDays),
                        DateTimeKind.Utc))
                .ToUnixTimeSeconds()
            : 0;

        return new DynamicClientRegistrationResponse
        {
            ClientId = client.ClientId,
            ClientIdIssuedAt = issuedAt,
            RedirectUris = RedirectUriSet(client).ToList(),
            GrantTypes = ["authorization_code", "refresh_token"],
            ResponseTypes = ["code"],
            TokenEndpointAuthMethod = "none",
            Scope = string.Join(' ', dcrOptions.AllowedScopes),
            ClientName = client.ClientName
        };
    }

    private static HashSet<string> RedirectUriSet(RtClient client)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (client.RedirectUris == null)
        {
            return set;
        }

        foreach (var entry in client.RedirectUris)
        {
            if (!string.IsNullOrEmpty(entry.Uri))
            {
                set.Add(entry.Uri);
            }
        }

        return set;
    }

    private static bool IsLoopbackHttp(string uri)
        => Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
           && parsed.Scheme == Uri.UriSchemeHttp
           && parsed.IsLoopback;

    private static DynamicClientRegistrationResult Disabled()
        => new(DynamicClientRegistrationOutcome.Disabled, null, null);

    private static DynamicClientRegistrationResult Invalid(string error, string description)
        => new(DynamicClientRegistrationOutcome.Invalid, null,
            new DynamicClientRegistrationError { Error = error, ErrorDescription = description });
}
