using AutoMapper;
using Duende.IdentityServer.Models;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class ClientStore : IOctoClientStore
{
    private readonly IMapper _mapper;
    private readonly IMultiTenancyResolverService _multiTenancyResolverService;
    private readonly IClientMirrorProvisioningService? _mirrorProvisioning;
    private readonly ILogger<ClientStore>? _logger;

    public ClientStore(IMultiTenancyResolverService multiTenancyResolverService, IMapper mapper)
    {
        _multiTenancyResolverService = multiTenancyResolverService;
        _mapper = mapper;
    }

    public ClientStore(
        IMultiTenancyResolverService multiTenancyResolverService,
        IMapper mapper,
        IClientMirrorProvisioningService mirrorProvisioning,
        ILogger<ClientStore> logger)
    {
        _multiTenancyResolverService = multiTenancyResolverService;
        _mapper = mapper;
        _mirrorProvisioning = mirrorProvisioning;
        _logger = logger;
    }

    private ITenantRepository TenantRepository => _multiTenancyResolverService.GetTenantRepository();

    public string TenantId => TenantRepository.TenantId;

    public async Task CreateAsync(RtClient octoClient)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.InsertOneRtEntityAsync(session, octoClient);

        await session.CommitTransactionAsync();
    }

    public async Task DeleteAsync(string clientId)
    {
        ArgumentValidation.ValidateString(nameof(clientId), clientId);

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var client = await GetClientByClientId(session, clientId);
        if (client == null)
        {
            throw new NotExistingException($"Client id '{clientId}' does not exist.");
        }

        var wasFlagged = client.AutoProvisionInChildTenants;
        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtClient>(session, client.RtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();

        // After the primary delete commits, fan out cleanup to any mirrors. Best-effort —
        // a failure here must not bubble back to the API caller because the delete itself
        // succeeded. If cleanup falls behind, the next ClientStore.DeleteAsync on the same
        // ClientId is a no-op (NotExistingException) but the mirrors live on until either
        // a tenant-delete (#4044) or the operator runs the backfill endpoint (#4045).
        if (wasFlagged && _mirrorProvisioning != null)
        {
            try
            {
                await _mirrorProvisioning.RemoveMirrorsForClientAsync(TenantId, clientId);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex,
                    "Mirror cleanup failed after deleting client '{ClientId}' in tenant '{TenantId}'",
                    clientId, TenantId);
            }
        }
    }

    public async Task<RtClient?> FindRtClientByIdAsync(string clientId)
    {
        ArgumentValidation.ValidateString(nameof(clientId), clientId);

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);


        await session.CommitTransactionAsync();
        var client = result.Items.FirstOrDefault();
        if (client == null)
        {
            return null;
        }

        return client;
    }

    public async Task<Client?> FindClientByIdAsync(string clientId, CancellationToken ct = default)
    {
        var client = await FindRtClientByIdAsync(clientId);

        ct.ThrowIfCancellationRequested();
        return _mapper.Map<Client>(client);
    }

    public async IAsyncEnumerable<Client> GetAllClientsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);

        await session.CommitTransactionAsync();

        foreach (var rtClient in result.Items)
        {
            ct.ThrowIfCancellationRequested();
            yield return _mapper.Map<Client>(rtClient);
        }
    }

    public async Task<IEnumerable<RtClient>> GetClients()
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items;
    }

    public async Task UpdateAsync(string clientId, RtClient client)
    {
        ArgumentValidation.ValidateString(nameof(clientId), clientId);

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var dbClient = await GetClientByClientId(session, clientId);
        if (dbClient == null)
        {
            throw new NotExistingException($"Client id '{clientId}' does not exist.");
        }

        await TenantRepository.ReplaceOneRtEntityByIdAsync(session, dbClient.RtId, client);

        await session.CommitTransactionAsync();

        // After the primary update commits, propagate to any mirrors. Best-effort:
        // a failure here must not break the API call. We use the post-update `client` here
        // (not `dbClient`) so secret rotation / scope updates / etc. take effect on mirrors.
        if (client.AutoProvisionInChildTenants && _mirrorProvisioning != null)
        {
            try
            {
                await _mirrorProvisioning.SyncMirrorsForClientAsync(TenantId, client);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex,
                    "Mirror sync failed after updating client '{ClientId}' in tenant '{TenantId}'",
                    clientId, TenantId);
            }
        }
    }



    private async Task<RtClient?> GetClientByClientId(IOctoSession session, string clientId)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }
}