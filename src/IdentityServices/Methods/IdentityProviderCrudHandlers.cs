using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Services.Methods.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared errors and audit details of the identity provider methods (System.Identity 3.8.0).</summary>
internal static class IdentityProviderMethodErrors
{
    /// <summary>A provider with this name exists.</summary>
    public const string IdentityProviderAlreadyExists = "IDENTITY_PROVIDER_ALREADY_EXISTS";

    /// <summary>OctoTenant: the parent tenant is not a trusted ancestor of this tenant.</summary>
    public const string ParentTenantNotAncestor = "PARENT_TENANT_NOT_ANCESTOR";

    /// <summary>No secret encryption key ring is configured; the client secret cannot be stored.</summary>
    public const string SecretEncryptionNotConfigured = "SECRET_ENCRYPTION_NOT_CONFIGURED";

    /// <summary>Audit detail: the concrete provider type of the call.</summary>
    public const string ProviderTypeDetail = "providerType";

    /// <summary>Audit detail: <c>true</c> when the call set a client secret (never the value).</summary>
    public const string ClientSecretSetDetail = "clientSecretSet";
}

/// <summary>
///     The configuration of an identity provider as the create and update methods take it (one parameter list for all provider
///     types) and the rules of the REST endpoints of <c>IdentityProvidersController</c>: the provider name rule, the required
///     fields per type (the REST DTO's <c>[Required]</c>), the defaults of the REST DTOs, and the write-only client secret.
/// </summary>
internal sealed record IdentityProviderConfiguration(
    string? Name,
    bool? Enabled,
    string? Description,
    bool? AllowSelfRegistration,
    string? DefaultGroupRtId,
    string? ClientId,
    string? ClientSecret,
    string? TenantId,
    string? Authority,
    string? Host,
    int? Port,
    bool? UseTls,
    string? UserBaseDn,
    string? UserNameAttribute,
    string? ParentTenantId)
{
    /// <summary>The default LDAP port of the REST DTOs.</summary>
    public const int DefaultLdapPort = 636;

    /// <summary>The default user name attribute of the OpenLDAP REST DTO.</summary>
    public const string DefaultUserNameAttribute = "uid";

    /// <summary>The provider types with a client secret (an OAuth application of an external provider).</summary>
    public static bool HasClientSecret(Type providerType) =>
        providerType == typeof(RtGoogleIdentityProvider) || providerType == typeof(RtMicrosoftIdentityProvider) ||
        providerType == typeof(RtFacebookIdentityProvider) || providerType == typeof(RtAzureEntraIdIdentityProvider);

    /// <summary>
    ///     The first invalid parameter for <paramref name="providerType" /> (name, reason), or <c>null</c>. A secret is required
    ///     on create only: on update an omitted secret keeps the stored one.
    /// </summary>
    public (string Parameter, string Reason)? Validate(Type providerType, bool isCreate)
    {
        if (!IdentityProvidersController.IsProviderNameValid(Name))
        {
            return ("name", "invalid");
        }

        if (HasClientSecret(providerType))
        {
            if (string.IsNullOrEmpty(ClientId))
            {
                return ("clientId", "required");
            }

            if (isCreate && string.IsNullOrEmpty(ClientSecret))
            {
                return ("clientSecret", "required");
            }
        }

        if (providerType == typeof(RtAzureEntraIdIdentityProvider) && string.IsNullOrEmpty(TenantId))
        {
            return ("tenantId", "required");
        }

        if (providerType == typeof(RtMicrosoftAdIdentityProvider) || providerType == typeof(RtOpenLdapIdentityProvider))
        {
            if (string.IsNullOrEmpty(Host))
            {
                return ("host", "required");
            }

            if (Port is < 1 or > 65535)
            {
                return ("port", "out-of-range");
            }
        }

        if (providerType == typeof(RtOpenLdapIdentityProvider) && string.IsNullOrEmpty(UserBaseDn))
        {
            return ("userBaseDn", "required");
        }

        if (providerType == typeof(RtOctoTenantIdentityProvider) && string.IsNullOrEmpty(ParentTenantId))
        {
            return ("parentTenantId", "required");
        }

        return null;
    }

    /// <summary>
    ///     The entity of <paramref name="providerType" /> with this configuration, as <c>IdentityProviderEntityMapping.ToEntity</c>
    ///     builds it from the REST DTO. A non-empty client secret is set as a pending Secret value (encrypted by the store); an
    ///     empty one is left out, so the store keeps the stored secret on a replace.
    /// </summary>
    public RtIdentityProvider ToEntity(Type providerType, OctoObjectId rtId)
    {
        RtIdentityProvider entity;
        if (providerType == typeof(RtGoogleIdentityProvider))
        {
            entity = new RtGoogleIdentityProvider { ClientId = ClientId! };
        }
        else if (providerType == typeof(RtMicrosoftIdentityProvider))
        {
            entity = new RtMicrosoftIdentityProvider { ClientId = ClientId! };
        }
        else if (providerType == typeof(RtFacebookIdentityProvider))
        {
            entity = new RtFacebookIdentityProvider { ClientId = ClientId! };
        }
        else if (providerType == typeof(RtAzureEntraIdIdentityProvider))
        {
            entity = new RtAzureEntraIdIdentityProvider
            {
                TenantId = TenantId!, Authority = Authority, ClientId = ClientId!
            };
        }
        else if (providerType == typeof(RtMicrosoftAdIdentityProvider))
        {
            entity = new RtMicrosoftAdIdentityProvider
            {
                Host = Host!, Port = Port ?? DefaultLdapPort, UseTls = UseTls ?? false
            };
        }
        else if (providerType == typeof(RtOpenLdapIdentityProvider))
        {
            entity = new RtOpenLdapIdentityProvider
            {
                Host = Host!, Port = Port ?? DefaultLdapPort, UserBaseDn = UserBaseDn!,
                UserNameAttribute = string.IsNullOrEmpty(UserNameAttribute) ? DefaultUserNameAttribute : UserNameAttribute,
                UseTls = UseTls ?? true
            };
        }
        else if (providerType == typeof(RtOctoTenantIdentityProvider))
        {
            entity = new RtOctoTenantIdentityProvider { ParentTenantId = ParentTenantId! };
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(providerType), providerType, "Not an identity provider type.");
        }

        entity.RtId = rtId;
        entity.Name = Name!;
        entity.Description = Description;
        entity.IsEnabled = Enabled ?? false;
        entity.AllowSelfRegistration = AllowSelfRegistration ?? true;
        entity.DefaultGroupRtId = DefaultGroupRtId;

        if (!string.IsNullOrEmpty(ClientSecret))
        {
            var pending = RtSecretValue.Pending(ClientSecret);
            switch (entity)
            {
                case RtGoogleIdentityProvider google:
                    google.ClientSecret = pending;
                    break;
                case RtMicrosoftIdentityProvider microsoft:
                    microsoft.ClientSecret = pending;
                    break;
                case RtFacebookIdentityProvider facebook:
                    facebook.ClientSecret = pending;
                    break;
                case RtAzureEntraIdIdentityProvider azureEntraId:
                    azureEntraId.ClientSecret = pending;
                    break;
            }
        }

        return entity;
    }
}

/// <summary>The concrete identity provider types and the shared write path of the create and update methods.</summary>
internal static class IdentityProviderMethodSupport
{
    private static readonly IReadOnlyDictionary<string, (RtCkId<CkTypeId> CkTypeId, Type Type)> ProviderTypes =
        new[]
        {
            Entry<RtGoogleIdentityProvider>(), Entry<RtMicrosoftIdentityProvider>(), Entry<RtFacebookIdentityProvider>(),
            Entry<RtAzureEntraIdIdentityProvider>(), Entry<RtMicrosoftAdIdentityProvider>(),
            Entry<RtOpenLdapIdentityProvider>(), Entry<RtOctoTenantIdentityProvider>()
        }.ToDictionary(e => e.Key, e => e.Value, StringComparer.OrdinalIgnoreCase);

    private static KeyValuePair<string, (RtCkId<CkTypeId>, Type)> Entry<T>() where T : RtIdentityProvider, new() =>
        new(CkTypeIdOf<T>(), (RtEntityExtensions.GetRtCkTypeId<T>(), typeof(T)));

    /// <summary>
    ///     The version-less CK type id of a provider type as a method request carries it (<c>System.Identity/OpenLdapIdentityProvider</c>,
    ///     the form of <see cref="CkMethodRequest.CkTypeId" /> and of the REST facades).
    /// </summary>
    public static string CkTypeIdOf<T>() where T : RtIdentityProvider => ModelName + "/" + typeof(T).Name[2..];

    private const string ModelName = "System.Identity";

    /// <summary>
    ///     The concrete provider type the request names, or <c>null</c> for anything else (the abstract
    ///     <c>IdentityProvider</c>, another type, nothing). Never taken from a parameter. A model version or major in the model
    ///     part (<c>System.Identity-3.8.0/...</c>, <c>System.Identity@3/...</c>) is ignored.
    /// </summary>
    public static (RtCkId<CkTypeId> CkTypeId, Type Type)? ProviderTypeOf(string? requestedCkTypeId)
    {
        if (string.IsNullOrEmpty(requestedCkTypeId))
        {
            return null;
        }

        var slash = requestedCkTypeId.IndexOf('/');
        if (slash <= 0)
        {
            return null;
        }

        var model = requestedCkTypeId[..slash];
        if (model.StartsWith(ModelName + "-", StringComparison.OrdinalIgnoreCase) ||
            model.StartsWith(ModelName + "@", StringComparison.OrdinalIgnoreCase))
        {
            model = ModelName;
        }

        return ProviderTypes.TryGetValue(model + requestedCkTypeId[slash..], out var type) ? type : null;
    }

    /// <summary>
    ///     Validates and stores the provider (insert or replace), then announces the change (<c>IdentityProviderUpdate</c>, the
    ///     login schemes reload). <c>null</c> on success, else the declared failure; nothing is stored on a failure.
    /// </summary>
    public static async Task<CkMethodFailure?> StoreAsync(IdentityMethodCall call, Type providerType,
        IdentityProviderConfiguration configuration, OctoObjectId rtId, RtIdentityProvider? existing)
    {
        call.Details[IdentityProviderMethodErrors.ProviderTypeDetail] = providerType.Name;
        if (configuration.Validate(providerType, existing == null) is { } invalid)
        {
            return CkMethodOutcome.ValidationFailed(invalid.Parameter, invalid.Reason).Failure;
        }

        call.Details[IdentityCrudErrors.NameDetail] = configuration.Name!;
        call.Details[IdentityProviderMethodErrors.ClientSecretSetDetail] =
            (!string.IsNullOrEmpty(configuration.ClientSecret)).ToString().ToLowerInvariant();

        var store = call.Services.GetRequiredService<IOctoIdentityProviderStore>();
        if (providerType == typeof(RtOctoTenantIdentityProvider) &&
            !await IsParentAdmittedAsync(call, store, configuration, existing).ConfigureAwait(false))
        {
            return new CkMethodFailure(IdentityProviderMethodErrors.ParentTenantNotAncestor);
        }

        try
        {
            await store.StoreAsync(configuration.ToEntity(providerType, rtId)).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsSecretEncryptionNotConfigured(ex))
        {
            return new CkMethodFailure(IdentityProviderMethodErrors.SecretEncryptionNotConfigured);
        }
        catch (DuplicateKeyException)
        {
            return new CkMethodFailure(IdentityProviderMethodErrors.IdentityProviderAlreadyExists);
        }

        await call.Services.GetRequiredService<IDistributionEventHubService>()
            .PublishAsync(new IdentityProviderUpdate(store.TenantId, Guid.NewGuid(), DateTime.Now)).ConfigureAwait(false);
        return null;
    }

    /// <summary>
    ///     The OctoTenant parent rule of the REST endpoint: the parent must be a trusted ancestor of this tenant, except when an
    ///     existing provider is disabled and keeps its stored parent (an operator can switch off a provider whose parent is gone).
    /// </summary>
    private static async Task<bool> IsParentAdmittedAsync(IdentityMethodCall call, IOctoIdentityProviderStore store,
        IdentityProviderConfiguration configuration, RtIdentityProvider? existing)
    {
        var parentTenantId = configuration.ParentTenantId!;
        if (configuration.Enabled != true && existing is RtOctoTenantIdentityProvider stored &&
            string.Equals(stored.ParentTenantId, parentTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        call.Details["parentTenantId"] = parentTenantId;
        return await call.Services.GetRequiredService<ICrossTenantAncestryGuard>()
            .IsTrustedAncestorAsync(store.TenantId, parentTenantId, "OctoTenant identity provider write")
            .ConfigureAwait(false);
    }

    private static bool IsSecretEncryptionNotConfigured(Exception? exception)
    {
        for (var current = exception; current != null; current = current.InnerException)
        {
            if (current is SecretEncryptionNotConfiguredException)
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
///     Handler of the static <c>System.Identity/IdentityProvider.CreateIdentityProvider-1</c> (System.Identity 3.8.0): creates a
///     provider of the concrete type of the call, as <c>POST system/v1/identityProviders</c> did. REST is its facade. The client
///     secret is stored as an encrypted Secret value and never part of the result or the audit.
/// </summary>
internal sealed class IdentityProviderCreateIdentityProviderHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<IdentityProviderCreateIdentityProviderParameters,
        IdentityProviderCreateIdentityProviderResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtIdentityProvider>();

    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override RtCkId<CkTypeId>? WrittenTypeOf(IdentityMethodCall call) =>
        IdentityProviderMethodSupport.ProviderTypeOf(call.RequestedCkTypeId)?.CkTypeId;

    protected override async Task<CkMethodOutcome<IdentityProviderCreateIdentityProviderResult>> CreateAsync(
        IdentityMethodCall call, IdentityProviderCreateIdentityProviderParameters p, CancellationToken cancellationToken)
    {
        var providerType = IdentityProviderMethodSupport.ProviderTypeOf(call.RequestedCkTypeId)!.Value.Type;
        var rtId = OctoObjectId.GenerateNewId();
        var failure = await IdentityProviderMethodSupport.StoreAsync(call, providerType,
            new IdentityProviderConfiguration(p.Name, p.Enabled, p.Description, p.AllowSelfRegistration, p.DefaultGroupRtId,
                p.ClientId, p.ClientSecret, p.TenantId, p.Authority, p.Host, p.Port, p.UseTls, p.UserBaseDn,
                p.UserNameAttribute, p.ParentTenantId), rtId, null).ConfigureAwait(false);
        return failure != null
            ? CkMethodOutcome<IdentityProviderCreateIdentityProviderResult>.Fail(failure)
            : new IdentityProviderCreateIdentityProviderResult { Value = rtId.ToString() };
    }

    protected override string? CreatedRtIdOf(IdentityProviderCreateIdentityProviderResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/IdentityProvider.UpdateIdentityProvider-1</c> (System.Identity 3.8.0): replaces a provider,
///     as <c>PUT system/v1/identityProviders/{rtId}</c> did; an omitted or empty client secret keeps the stored one. Called on
///     another concrete type than the stored provider's, the target is not found (the type of a provider never changes).
/// </summary>
internal sealed class IdentityProviderUpdateIdentityProviderHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<IdentityProviderUpdateIdentityProviderParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override RtEntityId? TargetEntityOf(IdentityMethodCall call, string methodId, OctoObjectId targetRtId) =>
        IdentityProviderMethodSupport.ProviderTypeOf(call.RequestedCkTypeId) is { } type
            ? new RtEntityId(type.CkTypeId, targetRtId)
            : (RtEntityId?)null;

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        IdentityProviderUpdateIdentityProviderParameters p, CancellationToken cancellationToken)
    {
        var providerType = IdentityProviderMethodSupport.ProviderTypeOf(call.RequestedCkTypeId)!.Value.Type;
        var existing = await call.Services.GetRequiredService<IOctoIdentityProviderStore>().GetByIdAsync(targetRtId)
            .ConfigureAwait(false);
        if (existing == null || existing.GetType() != providerType)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = existing.Name ?? string.Empty;
        var failure = await IdentityProviderMethodSupport.StoreAsync(call, providerType,
            new IdentityProviderConfiguration(p.Name, p.Enabled, p.Description,
                // A replace without allowSelfRegistration keeps the stored value: an omitted flag must never switch
                // self-registration on. The REST facade always sends the DTO's value (its class default is true).
                p.AllowSelfRegistration ?? existing.AllowSelfRegistration, p.DefaultGroupRtId,
                p.ClientId, p.ClientSecret, p.TenantId, p.Authority, p.Host, p.Port, p.UseTls, p.UserBaseDn,
                p.UserNameAttribute, p.ParentTenantId), targetRtId, existing).ConfigureAwait(false);
        return failure != null ? CkMethodOutcome.Fail(failure) : CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/IdentityProvider.DeleteIdentityProvider-1</c> (System.Identity 3.8.0): deletes a provider,
///     as <c>DELETE system/v1/identityProviders/{rtId}</c> did, and announces the change.
/// </summary>
internal sealed class IdentityProviderDeleteIdentityProviderHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<IdentityProviderDeleteIdentityProviderParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override RtEntityId? TargetEntityOf(IdentityMethodCall call, string methodId, OctoObjectId targetRtId) =>
        IdentityProviderMethodSupport.ProviderTypeOf(call.RequestedCkTypeId) is { } type
            ? new RtEntityId(type.CkTypeId, targetRtId)
            : (RtEntityId?)null;

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        IdentityProviderDeleteIdentityProviderParameters parameters, CancellationToken cancellationToken)
    {
        var providerType = IdentityProviderMethodSupport.ProviderTypeOf(call.RequestedCkTypeId)!.Value.Type;
        var store = call.Services.GetRequiredService<IOctoIdentityProviderStore>();
        var existing = await store.GetByIdAsync(targetRtId).ConfigureAwait(false);
        if (existing == null || existing.GetType() != providerType)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = existing.Name ?? string.Empty;
        call.Details[IdentityProviderMethodErrors.ProviderTypeDetail] = providerType.Name;
        await store.RemoveAsync(targetRtId).ConfigureAwait(false);
        await call.Services.GetRequiredService<IDistributionEventHubService>()
            .PublishAsync(new IdentityProviderUpdate(store.TenantId, Guid.NewGuid(), DateTime.Now)).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
