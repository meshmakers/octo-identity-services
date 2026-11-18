using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     The rules the API scope and API resource methods share with their REST endpoints: the caller rule
///     (<c>IdentityTenantAdministrationWritePolicy</c>), the definition the parameters describe, and the refresh of the
///     clients' CORS and scope caches after every write.
/// </summary>
internal static class ResourceDefinitions
{
    /// <summary>The caller rule of the resource methods: scope <c>octo_api</c> and <c>TenantManagement</c> or <c>UserManagement</c>.</summary>
    public static bool IsAdmitted(CkMethodPrincipal principal) => IdentityMethodCallerRules.IsTenantAdministrator(principal);

    /// <summary>Applies the definition of an API scope, as the REST body does (omitted user claims stay unchanged).</summary>
    public static void Apply(RtApiScope apiScope, string name, string? displayName, string? description, bool? enabled,
        bool? showInDiscoveryDocument, bool? required, bool? emphasized, IEnumerable<string>? userClaims)
    {
        apiScope.Enabled = enabled ?? false;
        apiScope.Name = name;
        apiScope.DisplayName = displayName;
        apiScope.Description = description;
        apiScope.ShowInDiscoveryDocument = showInDiscoveryDocument ?? false;
        if (userClaims != null)
        {
            apiScope.Claims = new AttributeStringValueList(userClaims.ToList());
        }

        apiScope.IsRequired = required ?? false;
        apiScope.IsEmphasized = emphasized ?? false;
    }

    /// <summary>
    ///     Applies the definition of an API resource, as the REST body does: omitted user claims and scopes stay unchanged,
    ///     omitted signing algorithms are the server default (empty). The secrets are never touched.
    /// </summary>
    public static void Apply(RtApiResource apiResource, string name, string? displayName, string? description,
        bool? enabled, bool? showInDiscoveryDocument, bool? requireResourceIndicator, IEnumerable<string>? userClaims,
        IEnumerable<string>? scopes, IEnumerable<string>? allowedAccessTokenSigningAlgorithms)
    {
        apiResource.Enabled = enabled ?? false;
        apiResource.Name = name;
        apiResource.DisplayName = displayName;
        apiResource.Description = description;
        apiResource.ShowInDiscoveryDocument = showInDiscoveryDocument ?? false;
        apiResource.RequireResourceIndicator = requireResourceIndicator ?? false;
        if (userClaims != null)
        {
            apiResource.Claims = new AttributeStringValueList(userClaims.ToList());
        }

        if (scopes != null)
        {
            apiResource.Scopes = new AttributeStringValueList(scopes.ToList());
        }

        apiResource.AllowedAccessTokenSigningAlgorithms =
            new AttributeStringValueList(allowedAccessTokenSigningAlgorithms?.ToList() ?? []);
    }

    /// <summary>Tells every replica to reload the clients' CORS origins and scopes of the tenant, as the REST writes do.</summary>
    public static Task PublishCacheRefreshAsync(IdentityMethodCall call, IOctoResourceStore store) =>
        call.Services.GetRequiredService<IDistributionEventHubService>()
            .PublishAsync(new CorsClientsUpdate(store.TenantId, Guid.NewGuid(), DateTime.Now));

    /// <summary><c>true</c> when an entity other than <paramref name="self" /> is in <paramref name="sameName" />.</summary>
    public static bool AnyOther<T>(IEnumerable<T> sameName, OctoObjectId? self) where T : RtEntity =>
        sameName.Any(e => self == null || e.RtId != self.Value);
}

/// <summary>
///     Handler of the static <c>System.Identity/ApiScope.CreateApiScope-1</c> (System.Identity 3.7.0), as
///     <c>POST system/v1/apiScopes</c> did: refuses an existing name (<c>API_SCOPE_ALREADY_EXISTS</c>), stores the scope and
///     refreshes the client caches.
/// </summary>
internal sealed class ApiScopeCreateApiScopeHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<ApiScopeCreateApiScopeParameters, ApiScopeCreateApiScopeResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtApiScope>();

    protected override bool IsAdmitted(CkMethodPrincipal principal) => ResourceDefinitions.IsAdmitted(principal);

    protected override async Task<CkMethodOutcome<ApiScopeCreateApiScopeResult>> CreateAsync(IdentityMethodCall call,
        ApiScopeCreateApiScopeParameters p, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(p.Name))
        {
            return CkMethodOutcome<ApiScopeCreateApiScopeResult>.ValidationFailed("name", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = p.Name;
        var store = call.Services.GetRequiredService<IOctoResourceStore>();
        if ((await store.FindRtApiScopesByNameAsync([p.Name]).ConfigureAwait(false)).Any())
        {
            return CkMethodOutcome<ApiScopeCreateApiScopeResult>.Fail(IdentityCrudErrors.ApiScopeAlreadyExists);
        }

        var apiScope = new RtApiScope();
        ResourceDefinitions.Apply(apiScope, p.Name, p.DisplayName, p.Description, p.Enabled, p.ShowInDiscoveryDocument,
            p.Required, p.Emphasized, p.UserClaims);
        await store.CreateApiScopeAsync(apiScope).ConfigureAwait(false);
        await ResourceDefinitions.PublishCacheRefreshAsync(call, store).ConfigureAwait(false);
        return new ApiScopeCreateApiScopeResult { Value = apiScope.RtId.ToString() };
    }

    protected override string? CreatedRtIdOf(ApiScopeCreateApiScopeResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/ApiScope.UpdateApiScope-1</c> (System.Identity 3.7.0), as
///     <c>PUT system/v1/apiScopes/{name}</c> did: replaces the definition and refreshes the client caches. A rename onto the
///     name of another scope is refused (<c>API_SCOPE_ALREADY_EXISTS</c>).
/// </summary>
internal sealed class ApiScopeUpdateApiScopeHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ApiScopeUpdateApiScopeParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) => ResourceDefinitions.IsAdmitted(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ApiScopeUpdateApiScopeParameters p, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IOctoResourceStore>();
        var apiScope = await store.GetApiScopeByIdAsync(targetRtId).ConfigureAwait(false);
        if (apiScope == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = apiScope.Name ?? string.Empty;
        if (string.IsNullOrWhiteSpace(p.Name))
        {
            return CkMethodOutcome.ValidationFailed("name", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = p.Name;
        if (ResourceDefinitions.AnyOther(await store.FindRtApiScopesByNameAsync([p.Name]).ConfigureAwait(false),
                apiScope.RtId))
        {
            return CkMethodOutcome.Fail(IdentityCrudErrors.ApiScopeAlreadyExists);
        }

        ResourceDefinitions.Apply(apiScope, p.Name, p.DisplayName, p.Description, p.Enabled, p.ShowInDiscoveryDocument,
            p.Required, p.Emphasized, p.UserClaims);
        await store.ReplaceApiScopeAsync(apiScope).ConfigureAwait(false);
        await ResourceDefinitions.PublishCacheRefreshAsync(call, store).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/ApiScope.DeleteApiScope-1</c> (System.Identity 3.7.0), as
///     <c>DELETE system/v1/apiScopes/{name}</c> did: erases the scope and refreshes the client caches.
/// </summary>
internal sealed class ApiScopeDeleteApiScopeHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ApiScopeDeleteApiScopeParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) => ResourceDefinitions.IsAdmitted(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ApiScopeDeleteApiScopeParameters parameters, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IOctoResourceStore>();
        var apiScope = await store.GetApiScopeByIdAsync(targetRtId).ConfigureAwait(false);
        if (apiScope == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = apiScope.Name ?? string.Empty;
        await store.DeleteApiScopeAsync(apiScope.RtId).ConfigureAwait(false);
        await ResourceDefinitions.PublishCacheRefreshAsync(call, store).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of the static <c>System.Identity/ApiResource.CreateApiResource-1</c> (System.Identity 3.7.0), as
///     <c>POST system/v1/apiResources</c> did: refuses an existing name (<c>API_RESOURCE_ALREADY_EXISTS</c>), stores the
///     resource without secrets and refreshes the client caches.
/// </summary>
internal sealed class ApiResourceCreateApiResourceHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<ApiResourceCreateApiResourceParameters, ApiResourceCreateApiResourceResult>(
        services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtApiResource>();

    protected override bool IsAdmitted(CkMethodPrincipal principal) => ResourceDefinitions.IsAdmitted(principal);

    protected override async Task<CkMethodOutcome<ApiResourceCreateApiResourceResult>> CreateAsync(
        IdentityMethodCall call, ApiResourceCreateApiResourceParameters p, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(p.Name))
        {
            return CkMethodOutcome<ApiResourceCreateApiResourceResult>.ValidationFailed("name", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = p.Name;
        var store = call.Services.GetRequiredService<IOctoResourceStore>();
        if ((await store.FindRtApiResourcesByNameAsync([p.Name]).ConfigureAwait(false)).Any())
        {
            return CkMethodOutcome<ApiResourceCreateApiResourceResult>.Fail(IdentityCrudErrors.ApiResourceAlreadyExists);
        }

        var apiResource = new RtApiResource();
        ResourceDefinitions.Apply(apiResource, p.Name, p.DisplayName, p.Description, p.Enabled,
            p.ShowInDiscoveryDocument, p.RequireResourceIndicator, p.UserClaims, p.Scopes,
            p.AllowedAccessTokenSigningAlgorithms);
        await store.CreateApiResourceAsync(apiResource).ConfigureAwait(false);
        await ResourceDefinitions.PublishCacheRefreshAsync(call, store).ConfigureAwait(false);
        return new ApiResourceCreateApiResourceResult { Value = apiResource.RtId.ToString() };
    }

    protected override string? CreatedRtIdOf(ApiResourceCreateApiResourceResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/ApiResource.UpdateApiResource-1</c> (System.Identity 3.7.0), as
///     <c>PUT system/v1/apiResources/{name}</c> did: one version-checked read-modify-write that keeps the stored secrets
///     (<c>CONCURRENT_CHANGE</c> when it loses), then the client cache refresh. A rename onto the name of another resource is
///     refused (<c>API_RESOURCE_ALREADY_EXISTS</c>).
/// </summary>
internal sealed class ApiResourceUpdateApiResourceHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ApiResourceUpdateApiResourceParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) => ResourceDefinitions.IsAdmitted(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ApiResourceUpdateApiResourceParameters p, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IOctoResourceStore>();
        var current = await store.GetApiResourceByIdAsync(targetRtId).ConfigureAwait(false);
        if (current == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = current.Name ?? string.Empty;
        if (string.IsNullOrWhiteSpace(p.Name))
        {
            return CkMethodOutcome.ValidationFailed("name", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = p.Name;
        if (ResourceDefinitions.AnyOther(await store.FindRtApiResourcesByNameAsync([p.Name]).ConfigureAwait(false),
                current.RtId))
        {
            return CkMethodOutcome.Fail(IdentityCrudErrors.ApiResourceAlreadyExists);
        }

        RtApiResource? stored;
        try
        {
            stored = await store.MutateApiResourceByIdAsync(targetRtId, apiResource =>
            {
                ResourceDefinitions.Apply(apiResource, p.Name, p.DisplayName, p.Description, p.Enabled,
                    p.ShowInDiscoveryDocument, p.RequireResourceIndicator, p.UserClaims, p.Scopes,
                    p.AllowedAccessTokenSigningAlgorithms);
                return true;
            }).ConfigureAwait(false);
        }
        catch (RtVersionConflictException)
        {
            return CkMethodOutcome.Fail(IdentityCrudErrors.ConcurrentChange);
        }

        if (stored == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        await ResourceDefinitions.PublishCacheRefreshAsync(call, store).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/ApiResource.DeleteApiResource-1</c> (System.Identity 3.7.0), as
///     <c>DELETE system/v1/apiResources/{name}</c> did: erases the resource with its secrets and refreshes the client caches.
/// </summary>
internal sealed class ApiResourceDeleteApiResourceHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ApiResourceDeleteApiResourceParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) => ResourceDefinitions.IsAdmitted(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ApiResourceDeleteApiResourceParameters parameters, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IOctoResourceStore>();
        var apiResource = await store.GetApiResourceByIdAsync(targetRtId).ConfigureAwait(false);
        if (apiResource == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = apiResource.Name ?? string.Empty;
        await store.DeleteApiResourceAsync(apiResource.RtId).ConfigureAwait(false);
        await ResourceDefinitions.PublishCacheRefreshAsync(call, store).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
