using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repository;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Commands.Payloads;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.Consumers;

public class CreateIdentityDataCommandRequestConsumer(ISystemContext systemContext) : IDistributedConsumer<CreateIdentityDataCommandRequest>
{
    public async Task ConsumeAsync(IDistributedContext<CreateIdentityDataCommandRequest> context)
    {
        var message = context.Message;

        ITenantContext tenantContext = systemContext;
        if (message.TenantId != systemContext.TenantId)
        {
            tenantContext = await systemContext.GetChildTenantContextAsync(message.TenantId);
        }

        var tenantRepository = tenantContext.GetTenantRepository();

        using var session = await tenantRepository.GetSessionAsync();
        try
        {
            session.StartTransaction();

            foreach (var distApiScopeDto in context.Message.ApiScopes)
            {
                await CreateApiScopeIfNotExistAsync(session, tenantRepository, distApiScopeDto);
            }

            foreach (var distApiResourcesDto in context.Message.ApiResources)
            {
                await CreateApiResourceIfNotExistAsync(session, tenantRepository, distApiResourcesDto);
            }

            foreach (var distClientDto in context.Message.Clients)
            {
                await CreateClientIfNotExistAsync(session, tenantRepository, distClientDto);
            }

            await session.CommitTransactionAsync();

            await context.RespondAsync(new GenericCommandResponse());
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    private async Task CreateApiScopeIfNotExistAsync(IOctoSession session, ITenantRepository tenantRepository,
        DistApiScopeDto distApiScopeDto)
    {
        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, distApiScopeDto.Name);

        var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, dataQueryOperation);
        if (!result.Items.Any())
        {
            var rtApiScope = new RtApiScope
            {
                Name = distApiScopeDto.Name,
                DisplayName = distApiScopeDto.DisplayName,
                Enabled = true
            };
            await tenantRepository.InsertOneRtEntityAsync(session, rtApiScope);
        }
    }

    private async Task CreateApiResourceIfNotExistAsync(IOctoSession session, ITenantRepository tenantRepository,
        DistApiResourcesDto distApiResourcesDto)
    {
        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.Equals, distApiResourcesDto.Name);

        var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, dataQueryOperation);
        if (!result.Items.Any())
        {
            var rtApiResource = new RtApiResource
            {
                Name = distApiResourcesDto.Name,
                DisplayName = distApiResourcesDto.DisplayName,
                Description = distApiResourcesDto.Description,
                Enabled = true,
                Scopes = new AttributeStringValueList(distApiResourcesDto.Scopes.ToList())
            };
            await tenantRepository.InsertOneRtEntityAsync(session, rtApiResource);
        }
    }

    private async Task CreateClientIfNotExistAsync(IOctoSession session, ITenantRepository tenantRepository, DistClientDto distClientDto)
    {
        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, distClientDto.ClientId);

        var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, dataQueryOperation);
        if (!result.Items.Any())
        {
            var rtClient = new RtClient
            {
                Enabled = true,
                ClientId = distClientDto.ClientId,

                ClientName = distClientDto.ClientName,
                ClientUri = distClientDto.ClientUri,

                AllowedGrantTypes = new AttributeStringValueList(distClientDto.AllowedGrantTypes.ToList()),

                RequirePkce = true,
                RequireClientSecret = false,

                AccessTokenType = RtTokenTypeEnum.Jwt,
                AllowAccessTokensViaBrowser = true,
                AlwaysIncludeUserClaimsInIdToken = true,
                RequireConsent = distClientDto.RequireConsent,

                RedirectUris = new AttributeStringValueList(distClientDto.RedirectUris.ToList()),
                PostLogoutRedirectUris = new AttributeStringValueList(distClientDto.PostLogoutRedirectUris.ToList()),
                AllowedCorsOrigins = new AttributeStringValueList(distClientDto.AllowedCorsOrigins.ToList()),
                AllowOfflineAccess = distClientDto.AllowOfflineAccess,
                AllowedScopes = new AttributeStringValueList(distClientDto.AllowedScopes.ToList())
            };
            await tenantRepository.InsertOneRtEntityAsync(session, rtClient);
        }
    }
}