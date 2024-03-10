using AutoMapper;
using Duende.IdentityServer.Models;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repository;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public class ClientStore : IOctoClientStore
{
    private readonly IMapper _mapper;
    private readonly ITenantRepository _tenantRepository;

    public ClientStore(IMultiTenancyResolverService multiTenancyResolverService, IMapper mapper)
    {
        _tenantRepository = multiTenancyResolverService.GetTenantRepository();
        _mapper = mapper;
    }
    
    public string TenantId => _tenantRepository.TenantId;   

    public async Task CreateAsync(RtClient octoClient)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        await _tenantRepository.InsertOneRtEntityAsync(session, octoClient);

        await session.CommitTransactionAsync();
    }

    public async Task DeleteAsync(string clientId)
    {
        ArgumentValidation.ValidateString(nameof(clientId), clientId);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var client = await GetClientByClientId(session, clientId);
        if (client == null)
        {
            throw new NotExistingException($"Client id '{clientId}' does not exist.");
        }

        await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtClient>(session, client.RtId);

        await session.CommitTransactionAsync();
    }

    public async Task<RtClient?> FindRtClientByIdAsync(string clientId)
    {
        ArgumentValidation.ValidateString(nameof(clientId), clientId);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, dataQueryOperation);


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
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var dataQueryOperation = DataQueryOperation.Create();

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, dataQueryOperation);

        await session.CommitTransactionAsync();
        return result.Items;
    }

    public async Task UpdateAsync(string clientId, RtClient client)
    {
        ArgumentValidation.ValidateString(nameof(clientId), clientId);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var dbClient = await GetClientByClientId(session, clientId);
        if (dbClient == null)
        {
            throw new NotExistingException($"Client id '{clientId}' does not exist.");
        }

        await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, dbClient.RtId, client);

        await session.CommitTransactionAsync();
    }



    private async Task<RtClient?> GetClientByClientId(IOctoSession session, string clientId)
    {
        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, dataQueryOperation);
        return result.Items.FirstOrDefault();
    }
}