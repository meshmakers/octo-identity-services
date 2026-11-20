using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Services.Methods.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared errors and audit details of the client CRUD methods (System.Identity 3.8.0).</summary>
internal static class ClientCrudErrors
{
    /// <summary>A client with this client id exists.</summary>
    public const string ClientAlreadyExists = "CLIENT_ALREADY_EXISTS";

    /// <summary>Audit detail: the OAuth client id.</summary>
    public const string ClientIdDetail = "clientId";

    /// <summary>Audit detail: <c>true</c> when the call set a client secret (never the value).</summary>
    public const string ClientSecretSetDetail = "clientSecretSet";
}

/// <summary>
///     A change of a client as the create and update methods take it: the fields of the REST <c>ClientDto</c> a caller may set.
///     <see cref="ApplyTo" /> is the rule the REST endpoints applied (an omitted value leaves the stored one; the allowed scopes
///     always include the octo default scopes; URIs carry the <c>api</c> source marker; a secret replaces all secrets with its
///     hash). The dynamic registration flags and <c>ProvisionedByParentTenantId</c> are no part of it.
/// </summary>
internal sealed record ClientChange(
    string? ClientId,
    bool? Enabled,
    string? ClientName,
    string? ClientUri,
    IReadOnlyList<string>? AllowedGrantTypes,
    IReadOnlyList<string>? RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris,
    IReadOnlyList<string>? AllowedCorsOrigins,
    IReadOnlyList<string>? AllowedScopes,
    bool? AllowOfflineAccess,
    bool? RequireClientSecret,
    string? ClientSecret,
    string? FrontChannelLogoutUri,
    bool? FrontChannelLogoutSessionRequired,
    string? BackChannelLogoutUri,
    bool? BackChannelLogoutSessionRequired,
    bool? AutoProvisionInChildTenants)
{
    /// <summary><c>true</c> when the change sets a client secret.</summary>
    public bool SetsSecret => !string.IsNullOrWhiteSpace(ClientSecret);

    /// <summary>
    ///     A new client with the protocol defaults the REST create set (the server-side part of the create). <c>Enabled</c>
    ///     defaults to <c>true</c>: the attribute is mandatory without a model default, so a create without it failed before.
    /// </summary>
    public static RtClient NewClient() => new()
    {
        Enabled = true,
        RequirePkce = true,
        RequireClientSecret = false,
        AccessTokenType = RtTokenTypeEnum.Jwt,
        AllowAccessTokensViaBrowser = true,
        AlwaysIncludeUserClaimsInIdToken = true,
        RequireConsent = false
    };

    /// <summary>
    ///     Applies the change to <paramref name="client" /> as the REST create and update did. Omitted <c>AllowedScopes</c>:
    ///     the octo default scopes on a create, unchanged on an update (the REST update facade passes an empty list for an
    ///     omitted body value, so REST keeps resetting them to the defaults).
    /// </summary>
    public void ApplyTo(RtClient client, bool isCreate)
    {
        if (Enabled.HasValue)
        {
            client.Enabled = Enabled.Value;
        }

        if (!string.IsNullOrEmpty(ClientId))
        {
            client.ClientId = ClientId;
        }

        if (!string.IsNullOrEmpty(ClientName))
        {
            client.ClientName = ClientName;
        }

        if (!string.IsNullOrEmpty(ClientUri))
        {
            client.ClientUri = ClientUri;
        }

        if (AllowedGrantTypes != null)
        {
            client.AllowedGrantTypes = new AttributeStringValueList(AllowedGrantTypes.ToList());
        }

        if (RedirectUris != null)
        {
            client.RedirectUris = WrapAsApiSourcedUris(RedirectUris);
        }

        if (PostLogoutRedirectUris != null)
        {
            client.PostLogoutRedirectUris = WrapAsApiSourcedUris(PostLogoutRedirectUris);
        }

        if (AllowedCorsOrigins != null)
        {
            client.AllowedCorsOrigins = WrapAsApiSourcedUris(AllowedCorsOrigins);
        }

        if (AllowedScopes != null)
        {
            client.AllowedScopes = new AttributeStringValueList(
                CommonConstants.OctoDefaultScopes.Concat(AllowedScopes).Distinct().ToList());
        }
        else if (isCreate)
        {
            client.AllowedScopes = new AttributeStringValueList(CommonConstants.OctoDefaultScopes.ToList());
        }

        if (AllowOfflineAccess.HasValue)
        {
            client.AllowOfflineAccess = AllowOfflineAccess.Value;
        }

        if (RequireClientSecret.HasValue)
        {
            client.RequireClientSecret = RequireClientSecret.Value;
        }

        if (SetsSecret)
        {
            client.ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = OctoSecretHasher.HashSecret(ClientSecret!) }
            };
        }

        // Single Logout (SLO) fields
        if (!string.IsNullOrEmpty(FrontChannelLogoutUri))
        {
            client.FrontChannelLogoutUri = FrontChannelLogoutUri;
        }

        if (FrontChannelLogoutSessionRequired.HasValue)
        {
            client.FrontChannelLogoutSessionRequired = FrontChannelLogoutSessionRequired.Value;
        }

        if (!string.IsNullOrEmpty(BackChannelLogoutUri))
        {
            client.BackChannelLogoutUri = BackChannelLogoutUri;
        }

        if (BackChannelLogoutSessionRequired.HasValue)
        {
            client.BackChannelLogoutSessionRequired = BackChannelLogoutSessionRequired.Value;
        }

        // Multi-tenant client credentials (#4042–#4047): the flag lands on the client; the store's post-commit hook fans
        // out to mirrors on an update. DynamicRegistration / DynamicRegistrationExpiresAt are deliberately not applied
        // (owned by DynamicClientRegistrationService and the TTL sweep).
        if (AutoProvisionInChildTenants.HasValue)
        {
            client.AutoProvisionInChildTenants = AutoProvisionInChildTenants.Value;
        }
    }

    /// <summary>
    ///     Wraps caller-supplied URIs as <see cref="RtClientUriEntryRecord" /> with <c>Source = api</c>: the cleanup gate keeps
    ///     them across blueprint re-applies.
    /// </summary>
    private static AttributeRecordValueList<RtClientUriEntryRecord> WrapAsApiSourcedUris(IEnumerable<string> uris)
    {
        var list = new AttributeRecordValueList<RtClientUriEntryRecord>();
        foreach (var uri in uris)
        {
            list.Add(new RtClientUriEntryRecord { Uri = uri, Source = ClientUriSources.Api });
        }

        return list;
    }
}

/// <summary>The rules the client create and update share: the secret role and the CORS refresh after a write.</summary>
internal static class ClientCrudSupport
{
    /// <summary>
    ///     A client secret in the parameters sets (replaces) the client's secret, the power of <c>Client.AddSecret</c>, so it
    ///     needs <c>SecretManagement</c> as REST <c>IdentitySecretAdministrationPolicy</c> (staged by
    ///     <c>SecretManagementRoleEnforcement</c>). <c>null</c> when the call sets no secret or the caller may set one.
    /// </summary>
    public static CkMethodFailure? CheckSecretCaller(IdentityMethodCall call, ClientChange change)
    {
        call.Details[ClientCrudErrors.ClientSecretSetDetail] = change.SetsSecret.ToString().ToLowerInvariant();
        if (!change.SetsSecret)
        {
            return null;
        }

        var decision = SecretOwnerMethodHandlerBase<RtClient>.DecideSecretCaller(call.Principal,
            call.Services.GetRequiredService<IOptionsMonitor<IdentityApiAuthorizationOptions>>().CurrentValue);
        if (decision == IdentityApiRoleDecision.AllowedByStagedWarn)
        {
            call.Services.GetRequiredService<ILogger<ClientChange>>().LogWarning(
                "Identity client secret method without required role allowed by SecretManagementRoleEnforcement=Warn by subject {Subject} / client {ClientId}, required any of [{RequiredRoles}]. " +
                "This would be denied with SecretManagementRoleEnforcement=Enforce",
                call.Principal.SubjectId, call.Principal.ClientId, CommonConstants.SecretManagementRole);
        }

        if (decision != IdentityApiRoleDecision.Denied)
        {
            return null;
        }

        call.Details["requiredRole"] = CommonConstants.SecretManagementRole;
        return SecretOwnerMethodHandlerBase<RtClient>.CallerForbidden();
    }

    /// <summary>Announces the change of the tenant's clients (CORS origins, client cache).</summary>
    public static Task PublishClientsUpdateAsync(IdentityMethodCall call) =>
        call.Services.GetRequiredService<IDistributionEventHubService>().PublishAsync(new CorsClientsUpdate(
            call.Services.GetRequiredService<IOctoClientStore>().TenantId, Guid.NewGuid(), DateTime.Now));
}

/// <summary>
///     Handler of the static <c>System.Identity/Client.CreateClient-1</c> (System.Identity 3.8.0): creates a client with the
///     protocol defaults of a new client, as <c>POST system/v1/clients</c> did. REST is its facade.
/// </summary>
/// <remarks>
///     Why a static method and not the generic create: the defaults (<see cref="ClientChange.NewClient" />), the octo default
///     scopes, the hash of the secret and the source marker of the URIs are generated on the server; a generic create would
///     store what the caller sends. No <c>replacesGenericCreate</c>: on the existing type Client the flag is a Major (row M16);
///     the generic create is refused for every caller since 3.6.0 (<c>writeAccess</c>), blueprint seeds use the system path.
/// </remarks>
internal sealed class ClientCreateClientHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<ClientCreateClientParameters, ClientCreateClientResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtClient>();

    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override async Task<CkMethodOutcome<ClientCreateClientResult>> CreateAsync(IdentityMethodCall call,
        ClientCreateClientParameters p, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(p.ClientId))
        {
            return CkMethodOutcome<ClientCreateClientResult>.ValidationFailed("clientId", "required");
        }

        var change = new ClientChange(p.ClientId, p.Enabled, p.ClientName, p.ClientUri, p.AllowedGrantTypes,
            p.RedirectUris, p.PostLogoutRedirectUris, p.AllowedCorsOrigins, p.AllowedScopes, p.AllowOfflineAccess,
            p.RequireClientSecret, p.ClientSecret, p.FrontChannelLogoutUri, p.FrontChannelLogoutSessionRequired,
            p.BackChannelLogoutUri, p.BackChannelLogoutSessionRequired, p.AutoProvisionInChildTenants);
        if (ClientCrudSupport.CheckSecretCaller(call, change) is { } secretDenied)
        {
            return CkMethodOutcome<ClientCreateClientResult>.Fail(secretDenied);
        }

        call.Details[ClientCrudErrors.ClientIdDetail] = p.ClientId;
        var store = call.Services.GetRequiredService<IOctoClientStore>();
        if (await store.FindRtClientByIdAsync(p.ClientId).ConfigureAwait(false) != null)
        {
            return new CkMethodFailure(ClientCrudErrors.ClientAlreadyExists);
        }

        var client = ClientChange.NewClient();
        change.ApplyTo(client, isCreate: true);
        await store.CreateAsync(client).ConfigureAwait(false);
        await ClientCrudSupport.PublishClientsUpdateAsync(call).ConfigureAwait(false);
        return new ClientCreateClientResult { Value = client.RtId.ToString() };
    }

    protected override string? CreatedRtIdOf(ClientCreateClientResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/Client.UpdateClient-1</c> (System.Identity 3.8.0): changes a client in one version-checked
///     read-modify-write, as <c>PUT system/v1/clients/{id}</c> did; an unresolved concurrent change is
///     <c>CONCURRENT_CHANGE</c>.
/// </summary>
internal sealed class ClientUpdateClientHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ClientUpdateClientParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ClientUpdateClientParameters p, CancellationToken cancellationToken)
    {
        var client = await IdentityMethodReads.FindAsync<RtClient>(call, targetRtId).ConfigureAwait(false);
        if (string.IsNullOrEmpty(client?.ClientId))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var change = new ClientChange(p.ClientId, p.Enabled, p.ClientName, p.ClientUri, p.AllowedGrantTypes,
            p.RedirectUris, p.PostLogoutRedirectUris, p.AllowedCorsOrigins, p.AllowedScopes, p.AllowOfflineAccess,
            p.RequireClientSecret, p.ClientSecret, p.FrontChannelLogoutUri, p.FrontChannelLogoutSessionRequired,
            p.BackChannelLogoutUri, p.BackChannelLogoutSessionRequired, p.AutoProvisionInChildTenants);
        if (ClientCrudSupport.CheckSecretCaller(call, change) is { } secretDenied)
        {
            return CkMethodOutcome.Fail(secretDenied);
        }

        call.Details[ClientCrudErrors.ClientIdDetail] = client.ClientId;
        try
        {
            var updated = await call.Services.GetRequiredService<IOctoClientStore>().MutateAsync(client.ClientId,
                current =>
                {
                    change.ApplyTo(current, isCreate: false);
                    return true;
                }).ConfigureAwait(false);
            if (updated == null)
            {
                return CkMethodOutcome.TargetNotFound();
            }
        }
        catch (RtVersionConflictException)
        {
            return CkMethodOutcome.Fail(new CkMethodFailure(IdentityCrudErrors.ConcurrentChange));
        }

        await ClientCrudSupport.PublishClientsUpdateAsync(call).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.DeleteClient-1</c> (System.Identity 3.8.0): deletes a client, as
///     <c>DELETE system/v1/clients/{id}</c> did.
/// </summary>
internal sealed class ClientDeleteClientHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ClientDeleteClientParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ClientDeleteClientParameters parameters, CancellationToken cancellationToken)
    {
        var client = await IdentityMethodReads.FindAsync<RtClient>(call, targetRtId).ConfigureAwait(false);
        if (string.IsNullOrEmpty(client?.ClientId))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[ClientCrudErrors.ClientIdDetail] = client.ClientId;
        await call.Services.GetRequiredService<IOctoClientStore>().DeleteAsync(client.ClientId).ConfigureAwait(false);
        await ClientCrudSupport.PublishClientsUpdateAsync(call).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
