using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
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
        var session = await TenantRepository.GetSessionAsync();
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
    // Note: the Rt strong-typed ClientSecret property throws InvalidAttributeValueException if
    // the underlying attribute is null, so read via GetAttributeStringValueOrDefault and write
    // back through the typed setter (which stores via the attribute dictionary).
    private const string ClientSecretAttributeName = "ClientSecret";

    private static void PreserveOAuthClientSecretIfOmitted(RtIdentityProvider incoming,
        RtIdentityProvider existing)
    {
        switch (incoming)
        {
            case RtGoogleIdentityProvider g when existing is RtGoogleIdentityProvider exG
                                                 && IsClientSecretOmitted(g):
                g.ClientSecret = exG.ClientSecret;
                break;
            case RtMicrosoftIdentityProvider m when existing is RtMicrosoftIdentityProvider exM
                                                    && IsClientSecretOmitted(m):
                m.ClientSecret = exM.ClientSecret;
                break;
            case RtFacebookIdentityProvider f when existing is RtFacebookIdentityProvider exF
                                                   && IsClientSecretOmitted(f):
                f.ClientSecret = exF.ClientSecret;
                break;
            case RtAzureEntraIdIdentityProvider a when existing is RtAzureEntraIdIdentityProvider exA
                                                       && IsClientSecretOmitted(a):
                a.ClientSecret = exA.ClientSecret;
                break;
        }
    }

    private static bool IsClientSecretOmitted(RtIdentityProvider entity)
    {
        var value = entity.GetAttributeStringValueOrDefault(ClientSecretAttributeName);
        return string.IsNullOrEmpty(value);
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtIdentityProvider>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }
}