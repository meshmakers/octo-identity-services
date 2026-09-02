using IdentityModel;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using IdentityServerPersistence;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands.Payloads;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Consumers;

// ReSharper disable once ClassNeverInstantiated.Global
public class CreateIdentityDataCommandRequestConsumer(
    ILogger<CreateIdentityDataCommandRequestConsumer> logger,
    ISystemContext systemContext)
    : IDistributedConsumer<CreateIdentityDataCommandRequest>
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

        // That means that the tenant is not configured to use an
        // own identity management. We do nothing in this case and return information to the producer
        if (!await tenantContext.IsCkModelExistingAsync(SystemIdentityCkIds.CkModelId))
        {
            await context.RespondAsync(new EnumCommandResponse<CreateIdentityDataResult>
            { Response = CreateIdentityDataResult.FailedTenantHasNoIdentityCk });
            return;
        }

        using var session = await tenantRepository.GetSessionAsync();
        try
        {
            session.StartTransaction();

            if (context.Message.ApiScopes != null)
            {
                foreach (var distApiScopeDto in context.Message.ApiScopes)
                {
                    await CreateApiScopeIfNotExistAsync(session, tenantRepository, distApiScopeDto);
                }
            }

            if (context.Message.ApiResources != null)
            {
                foreach (var distApiResourcesDto in context.Message.ApiResources)
                {
                    await CreateApiResourceIfNotExistAsync(session, tenantRepository, distApiResourcesDto);
                }
            }

            if (context.Message.Clients != null)
            {
                foreach (var distClientDto in context.Message.Clients)
                {
                    await CreateClientIfNotExistAsync(session, tenantRepository, distClientDto);
                }
            }

            await session.CommitTransactionAsync();

            // The work above only covers the *caller's* identity data (its API scopes, resources and
            // clients). The tenant's own default configuration — roles, groups, TenantOwners — is seeded by
            // this service's SetupTenantAsync via the System.Identity.Bootstrap blueprint, which runs on a
            // completely different trigger and can fail independently. Reporting Success regardless made
            // the caller mark the tenant fully provisioned while it had no roles at all, so no administrator
            // could ever be provisioned (AB#4690). Report the difference instead of hiding it.
            var seeded = await HasIdentityDataSeedAsync(tenantRepository);
            if (!seeded)
            {
                logger.LogWarning(
                    "Identity data for tenant '{TenantId}' was created, but the tenant has no roles yet — " +
                    "its identity default configuration is not seeded. Reporting seed-pending so the caller retries.",
                    message.TenantId);
            }

            await context.RespondAsync(new EnumCommandResponse<CreateIdentityDataResult>
            {
                Response = seeded
                    ? CreateIdentityDataResult.Success
                    : CreateIdentityDataResult.SuccessIdentityDataSeedPending
            });
        }
        catch (Exception e)
        {
            logger.LogError(e, "Error while creating identity data");
            throw;
        }
    }

    /// <summary>
    /// True when the tenant's identity default configuration has been seeded. Roles are the discriminator:
    /// they are what <c>ProvisionCurrentUser</c> needs and the first thing the
    /// <c>System.Identity.Bootstrap</c> blueprint installs, so "no roles" is exactly the half-provisioned
    /// state we must not report as success (AB#4690).
    /// </summary>
    private static async Task<bool> HasIdentityDataSeedAsync(ITenantRepository tenantRepository)
    {
        using var session = await tenantRepository.GetSessionAsync();
        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session,
            RtEntityQueryOptions.Create(), take: 1);
        return roles.Items.Any();
    }

    private static async Task CreateApiScopeIfNotExistAsync(IOctoSession session, ITenantRepository tenantRepository,
        DistApiScopeDto distApiScopeDto)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, distApiScopeDto.Name);

        var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, queryOptions);
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

    private static async Task CreateApiResourceIfNotExistAsync(IOctoSession session, ITenantRepository tenantRepository,
        DistApiResourcesDto distApiResourcesDto)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.Equals, distApiResourcesDto.Name);

        var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, queryOptions);
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

    private async Task CreateClientIfNotExistAsync(IOctoSession session, ITenantRepository tenantRepository,
        DistClientDto distClientDto)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, distClientDto.ClientId);

        var rtClient = new RtClient
        {
            Enabled = true,
            ClientId = distClientDto.ClientId,

            ClientName = distClientDto.ClientName,
            ClientUri = distClientDto.ClientUri,

            AllowedGrantTypes = new AttributeStringValueList(distClientDto.AllowedGrantTypes.ToList()),

            RequirePkce = true,
            // AB#5027: was hard-coded false. Still false for every producer that predates the
            // property, so nothing about the existing swagger/SPA clients changes; a
            // client_credentials service account sets it to true and ships a secret below.
            RequireClientSecret = distClientDto.RequireClientSecret,

            AccessTokenType = RtTokenTypeEnum.Jwt,
            AllowAccessTokensViaBrowser = true,
            AlwaysIncludeUserClaimsInIdToken = true,
            RequireConsent = distClientDto.RequireConsent,

            RedirectUris = WrapAsBaseSourcedUris(distClientDto.RedirectUris),
            PostLogoutRedirectUris = WrapAsBaseSourcedUris(distClientDto.PostLogoutRedirectUris),
            AllowedCorsOrigins = WrapAsBaseSourcedUris(distClientDto.AllowedCorsOrigins),
            AllowOfflineAccess = distClientDto.AllowOfflineAccess,
            AllowedScopes = new AttributeStringValueList(distClientDto.AllowedScopes.ToList()),

            // Single Logout (SLO) configuration
            FrontChannelLogoutUri = distClientDto.FrontChannelLogoutUri,
            FrontChannelLogoutSessionRequired = distClientDto.FrontChannelLogoutSessionRequired,
            BackChannelLogoutUri = distClientDto.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = distClientDto.BackChannelLogoutSessionRequired
        };

        var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);
        var existingClient = result.Items.FirstOrDefault();

        // AB#5027 — client secret. The producer sends the PLAINTEXT; only the SHA-256 hash
        // (the legacy shared-secret convention OctoSecretHasher implements, identical to
        // ClientsController — a drift here silently makes every provisioned client
        // unauthenticatable) is ever stored; the plaintext is never logged, echoed or persisted.
        //
        // Order of preference is what makes a second provisioning run a no-op:
        //   * a plaintext arrived  -> (re-)issue: replace the secret list with its hash.
        //   * nothing arrived      -> PRESERVE whatever the existing client already has. Without
        //     this the wholesale ReplaceOneRtEntityByIdAsync below would silently drop a live
        //     secret on the next identity-data pass — harmless while no bus client had one,
        //     fatal now that a service account does.
        if (!string.IsNullOrWhiteSpace(distClientDto.ClientSecret))
        {
            rtClient.ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = OctoSecretHasher.HashSecret(distClientDto.ClientSecret) }
            };
        }
        else if (existingClient != null)
        {
            rtClient.ClientSecrets = existingClient.ClientSecrets;
        }

        OctoObjectId clientRtId;
        if (existingClient == null)
        {
            await tenantRepository.InsertOneRtEntityAsync(session, rtClient);
            clientRtId = rtClient.RtId;
        }
        else
        {
            clientRtId = existingClient.RtId;
            await tenantRepository.ReplaceOneRtEntityByIdAsync(session, clientRtId, rtClient);
        }

        await EnsureAssignedRolesAsync(session, tenantRepository, clientRtId, distClientDto);
    }

    /// <summary>
    ///     AB#5027: assigns the requested roles to the client through the <c>AssignedRole</c>
    ///     association — the same edge <c>ClientRoleStore</c> writes, so the roles land in the
    ///     <c>client_credentials</c> token via <c>TokenEndpointController.HandleClientCredentialsAsync</c>.
    ///     <para>
    ///     <c>IClientRoleStore</c> cannot be used from here: it resolves its repository through
    ///     <c>IMultiTenancyResolverService.GetTenantRepository()</c>, i.e. the HTTP-scoped tenant, and
    ///     this consumer runs on the message bus with no HTTP context — it would silently write into
    ///     the system tenant. The association is therefore written directly against the tenant
    ///     repository this consumer already resolved from the message.
    ///     </para>
    ///     <para>
    ///     Additive and idempotent: existing edges are left alone, roles the DTO does not mention are
    ///     never removed (the client may legitimately have been granted more by an operator), and an
    ///     unknown role name is logged and skipped rather than failing the whole identity-data setup —
    ///     the roles seed (<c>System.Identity.Bootstrap</c>) runs on an independent trigger and may
    ///     legitimately not have landed yet, which the caller already handles via
    ///     <see cref="CreateIdentityDataResult.SuccessIdentityDataSeedPending" />.
    ///     </para>
    /// </summary>
    private async Task EnsureAssignedRolesAsync(IOctoSession session, ITenantRepository tenantRepository,
        OctoObjectId clientRtId, DistClientDto distClientDto)
    {
        if (distClientDto.AssignedRoleNames == null || distClientDto.AssignedRoleNames.Length == 0)
        {
            return;
        }

        var clientEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), clientRtId);

        var currentAssociations = await tenantRepository.GetRtAssociationsAsync(
            session,
            clientEntityId,
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        var currentRoleIds = currentAssociations.Items.Select(a => a.TargetRtId.ToString()).ToHashSet();

        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
        var updates = new List<AssociationUpdateInfo>();

        foreach (var roleName in distClientDto.AssignedRoleNames.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // Role lookups key off the upper-invariant NormalizedName everywhere in this service.
            var roleQuery = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals,
                    roleName.ToUpperInvariant());
            var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, roleQuery, take: 1);
            var role = roles.Items.FirstOrDefault();
            if (role == null)
            {
                logger.LogWarning(
                    "Role '{RoleName}' requested for client '{ClientId}' in tenant '{TenantId}' does not exist; " +
                    "the client is created without it. Re-run the identity data setup once the tenant's role seed is in place.",
                    roleName, distClientDto.ClientId, tenantRepository.TenantId);
                continue;
            }

            if (currentRoleIds.Contains(role.RtId.ToString()))
            {
                continue;
            }

            updates.Add(AssociationUpdateInfo.CreateInsert(
                clientEntityId,
                new RtEntityId(roleCkTypeId, role.RtId),
                IdentityAssociationConstants.AssignedRoleId));
        }

        if (updates.Count == 0)
        {
            return;
        }

        var operationResult = new OperationResult();
        await tenantRepository.ApplyChangesAsync(session, updates, operationResult);
        if (operationResult.HasErrors || operationResult.HasFatalErrors)
        {
            throw new InvalidOperationException(
                $"Failed to assign roles to client '{distClientDto.ClientId}' in tenant '{tenantRepository.TenantId}': " +
                string.Join("; ", operationResult.GetMessages()));
        }

        logger.LogInformation(
            "Assigned {RoleCount} role(s) to client '{ClientId}' in tenant '{TenantId}'",
            updates.Count, distClientDto.ClientId, tenantRepository.TenantId);
    }

    /// <summary>
    ///     Wraps cross-service-pushed URI strings as <see cref="ClientUriEntry"/> records with
    ///     <c>Source = <see cref="IdentityServerPersistence.ClientUriSources.Base"/></c>. Reason: the
    ///     distribution-event-hub identity bootstrap mirrors blueprint-managed clients into child
    ///     tenants, so these entries are conceptually blueprint-seeded data flowing across services
    ///     and DO get rewritten on every blueprint re-apply — which is fine because the next event-hub
    ///     message re-creates them.
    /// </summary>
    private static AttributeRecordValueList<RtClientUriEntryRecord> WrapAsBaseSourcedUris(IEnumerable<string> uris)
    {
        var list = new AttributeRecordValueList<RtClientUriEntryRecord>();
        foreach (var uri in uris)
        {
            list.Add(new RtClientUriEntryRecord { Uri = uri, Source = IdentityServerPersistence.ClientUriSources.Base });
        }

        return list;
    }
}