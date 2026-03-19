using AutoMapper;
using Duende.IdentityServer.Models;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class ClientStore : IOctoClientStore
{
    private readonly IMapper _mapper;
    private readonly IMultiTenancyResolverService _multiTenancyResolverService;

    public ClientStore(IMultiTenancyResolverService multiTenancyResolverService, IMapper mapper)
    {
        _multiTenancyResolverService = multiTenancyResolverService;
        _mapper = mapper;
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

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtClient>(session, client.RtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
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

    public async Task<Client?> FindClientByIdAsync(string clientId)
    {
        var client = await FindRtClientByIdAsync(clientId);

        return _mapper.Map<Client>(client);
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
    }



    private async Task<RtClient?> GetClientByClientId(IOctoSession session, string clientId)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }
}