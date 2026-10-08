using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class IdentityProviderStore(IMultiTenancyResolverService multiTenancyResolverService)
    : IOctoIdentityProviderStore
{
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public string TenantId => TenantRepository.TenantId;

    public async Task<RtIdentityProvider?> GetByNameAsync(string name)
    {
        ArgumentValidation.ValidateString(nameof(name), name);

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtIdentityProvider.Name), name)
            .FieldEquals(nameof(RtIdentityProvider.IsEnabled), true);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.SingleOrDefault();
    }

    public async Task<RtIdentityProvider?> GetByIdAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(session, rtId);

        await session.CommitTransactionAsync();
        return result;
    }


    public async Task<IEnumerable<RtIdentityProvider>> GetAllAsync()
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task StoreAsync(RtIdentityProvider identityProvider)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(session, identityProvider.RtId);
        if (result == null)
        {
            await TenantRepository.InsertOneRtEntityAsync(session, identityProvider);
        }
        else
        {
            PreserveOAuthClientSecretIfOmitted(identityProvider, result);
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, identityProvider.RtId, identityProvider);
        }

        await session.CommitTransactionAsync();
    }

    // On update, the Refinery Studio UI deliberately omits ClientSecret when the user does not
    // re-enter it ("Secret is stored encrypted on the server. SET NEW SECRET"). Without this
    // preserve step the stored secret would be overwritten with null on every edit. ADO #4199.
    //
    // Since AB#5540 ClientSecret is a Secret attribute (RtSecretValue). The engine's write step
    // already carries an omitted / "" secret over on replace (concept §3.6); this explicit copy of
    // the STORED value (a protected envelope, or legacy text before the encrypt sweep) is kept as
    // defense in depth and so the replace never depends on the repository implementation. The
    // value is copied as is — it is never decrypted here.
    private const string ClientSecretAttributeName = "ClientSecret";
    private static readonly RtSecretValue EmptyPending = RtSecretValue.Pending(string.Empty);

    private static void PreserveOAuthClientSecretIfOmitted(RtIdentityProvider incoming,
        RtIdentityProvider existing)
    {
        if (!HasClientSecret(incoming) || incoming.GetType() != existing.GetType()
                                       || !IsClientSecretOmitted(incoming))
        {
            return;
        }

        var stored = existing.GetAttributeSecretValueOrDefault(ClientSecretAttributeName);
        if (stored != null)
        {
            incoming.SetAttributeValue(ClientSecretAttributeName, AttributeValueTypesDto.Secret, stored);
        }
    }

    private static bool HasClientSecret(RtIdentityProvider entity)
        => entity is RtGoogleIdentityProvider or RtMicrosoftIdentityProvider or RtFacebookIdentityProvider
            or RtAzureEntraIdIdentityProvider;

    // Omitted = not set, or a pending (newly entered) value that is empty. A marker sent back by a
    // client ({"isSet":true}) also deserialises to Pending("") and therefore means "unchanged".
    private static bool IsClientSecretOmitted(RtIdentityProvider entity)
    {
        var value = entity.GetAttributeSecretValueOrDefault(ClientSecretAttributeName);
        return value == null || value == EmptyPending;
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtIdentityProvider>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }
}