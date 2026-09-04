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
        await EnsureMayActAsEdgesAsync(session, tenantRepository, clientRtId, distClientDto);
    }

    /// <summary>
    ///     AB#5114: materialises the <c>System.Identity/MayActAs</c> edges declared by
    ///     <see cref="DistClientDto.MayActAsClientIds" /> — for every named ACTOR client id that
    ///     resolves in the tenant, ensures the edge actor→<b>this</b> client. The edge is what the
    ///     impersonation grant and the on-behalf-of <c>requested_client_id</c> extension authorize
    ///     against, so this is the bus-side half of secretless pipeline service accounts: the
    ///     Communication Controller declares "this adapter may act as this SA" on the same message
    ///     that provisions the SA.
    ///     <para>
    ///     Additive and idempotent, exactly like the pre-AB#5111 role semantics — deliberately NOT
    ///     the declarative sync <see cref="EnsureAssignedRolesAsync" /> applies to prefixed
    ///     clients: an edge is an authorization another producer or an operator may legitimately
    ///     have granted, and v1 has no safe signal to distinguish "not mine" from "revoked".
    ///     Existing edges are left alone, edges to actors not in the list are never removed, and
    ///     an unknown actor client id is skipped with a warning rather than failing the whole
    ///     identity-data setup — the actor's client may simply arrive on a later provisioning pass
    ///     (seed ordering), mirroring the unresolvable-role handling. A <c>null</c> list (every
    ///     pre-AB#5114 producer) changes nothing.
    ///     </para>
    /// </summary>
    private async Task EnsureMayActAsEdgesAsync(IOctoSession session, ITenantRepository tenantRepository,
        OctoObjectId clientRtId, DistClientDto distClientDto)
    {
        if (distClientDto.MayActAsClientIds == null || distClientDto.MayActAsClientIds.Count == 0)
        {
            return;
        }

        var clientCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtClient>();
        var targetEntityId = new RtEntityId(clientCkTypeId, clientRtId);
        var updates = new List<AssociationUpdateInfo>();

        foreach (var actorClientId in distClientDto.MayActAsClientIds
                     .Where(id => !string.IsNullOrWhiteSpace(id))
                     .Distinct(StringComparer.Ordinal))
        {
            if (string.Equals(actorClientId, distClientDto.ClientId, StringComparison.Ordinal))
            {
                // A self-edge would state "this client may become itself" — meaningless, and a
                // likely producer bug worth surfacing.
                logger.LogWarning(
                    "MayActAs actor '{ActorClientId}' declared for client '{ClientId}' in tenant '{TenantId}' names the client itself; skipped.",
                    actorClientId, distClientDto.ClientId, tenantRepository.TenantId);
                continue;
            }

            var actorQuery = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, actorClientId);
            var actors = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, actorQuery, take: 1);
            var actor = actors.Items.FirstOrDefault();
            if (actor == null)
            {
                logger.LogWarning(
                    "MayActAs actor client '{ActorClientId}' declared for client '{ClientId}' in tenant '{TenantId}' does not exist; " +
                    "the edge is skipped. Re-run the identity data setup once the actor client is provisioned.",
                    actorClientId, distClientDto.ClientId, tenantRepository.TenantId);
                continue;
            }

            var actorEntityId = new RtEntityId(clientCkTypeId, actor.RtId);
            var existing = await tenantRepository.GetRtAssociationOrDefaultAsync(
                session, actorEntityId, targetEntityId, IdentityAssociationConstants.MayActAsId);
            if (existing != null)
            {
                continue;
            }

            updates.Add(AssociationUpdateInfo.CreateInsert(
                actorEntityId, targetEntityId, IdentityAssociationConstants.MayActAsId));
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
                $"Failed to materialise MayActAs edges for client '{distClientDto.ClientId}' in tenant '{tenantRepository.TenantId}': " +
                string.Join("; ", operationResult.GetMessages()));
        }

        logger.LogInformation(
            "Materialised {EdgeCount} MayActAs edge(s) towards client '{ClientId}' in tenant '{TenantId}'",
            updates.Count, distClientDto.ClientId, tenantRepository.TenantId);
    }

    /// <summary>
    ///     AB#5111: client-id prefix of the Communication Controller's pipeline service accounts
    ///     (<c>PipelineServiceAccountProvisioningService.BuildClientId</c>). For clients under this
    ///     prefix a non-null <c>AssignedRoleNames</c> is a <b>declaration</b> and the role edges are
    ///     fully synced (add missing, remove superfluous); every other client keeps the additive
    ///     AB#5027 semantics. The prefix is the only signal available: <c>DistClientDto</c> lives in
    ///     octo-common-services and gaining a "sync mode" property there would force a contract
    ///     release across every producer for a behaviour only these clients want.
    /// </summary>
    internal const string PipelineServiceAccountClientIdPrefix = "octo-pipeline-sa-";

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
    ///     Additive and idempotent by default: existing edges are left alone, roles the DTO does not
    ///     mention are never removed (the client may legitimately have been granted more by an
    ///     operator), and an unknown role name is logged and skipped rather than failing the whole
    ///     identity-data setup — the roles seed (<c>System.Identity.Bootstrap</c>) runs on an
    ///     independent trigger and may legitimately not have landed yet, which the caller already
    ///     handles via <see cref="CreateIdentityDataResult.SuccessIdentityDataSeedPending" />.
    ///     </para>
    ///     <para>
    ///     AB#5111 exception — declarative sync for pipeline service accounts (client-id prefix
    ///     <see cref="PipelineServiceAccountClientIdPrefix" />): a non-null role list on such a
    ///     client is its complete declaration, so edges to roles outside the list are removed. Two
    ///     safeties keep that from destroying anything by accident: a <c>null</c> list still means
    ///     "leave the roles alone" (the controller sends null for legacy, undeclared accounts and
    ///     for rotations), and removal is skipped entirely while any declared role name is
    ///     unresolvable — half a declaration must not delete the surviving half.
    ///     </para>
    /// </summary>
    private async Task EnsureAssignedRolesAsync(IOctoSession session, ITenantRepository tenantRepository,
        OctoObjectId clientRtId, DistClientDto distClientDto)
    {
        if (distClientDto.AssignedRoleNames == null)
        {
            return;
        }

        // AB#5111: declared service accounts sync fully; everyone else stays additive — and for
        // them an empty list means "nothing to add", exactly as before.
        var isDeclarativeSync = distClientDto.ClientId.StartsWith(PipelineServiceAccountClientIdPrefix,
            StringComparison.Ordinal);
        if (!isDeclarativeSync && distClientDto.AssignedRoleNames.Length == 0)
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
        var declaredRoleIds = new HashSet<string>();
        var allDeclaredRolesResolved = true;

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
                allDeclaredRolesResolved = false;
                logger.LogWarning(
                    "Role '{RoleName}' requested for client '{ClientId}' in tenant '{TenantId}' does not exist; " +
                    "the client is created without it. Re-run the identity data setup once the tenant's role seed is in place.",
                    roleName, distClientDto.ClientId, tenantRepository.TenantId);
                continue;
            }

            declaredRoleIds.Add(role.RtId.ToString());

            if (currentRoleIds.Contains(role.RtId.ToString()))
            {
                continue;
            }

            updates.Add(AssociationUpdateInfo.CreateInsert(
                clientEntityId,
                new RtEntityId(roleCkTypeId, role.RtId),
                IdentityAssociationConstants.AssignedRoleId));
        }

        var removedCount = 0;
        if (isDeclarativeSync && allDeclaredRolesResolved)
        {
            // AB#5111: the declaration is complete and fully resolvable — edges outside it go. Skipped
            // while any name is unresolvable (seed pending): removing the known-good edges because the
            // seed has not landed would take a working service account down for a transient reason.
            foreach (var association in currentAssociations.Items
                         .Where(a => !declaredRoleIds.Contains(a.TargetRtId.ToString())))
            {
                removedCount++;
                updates.Add(AssociationUpdateInfo.CreateDelete(
                    clientEntityId,
                    new RtEntityId(roleCkTypeId, association.TargetRtId),
                    IdentityAssociationConstants.AssignedRoleId));
            }
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
            "Synced roles of client '{ClientId}' in tenant '{TenantId}': {AddedCount} added, {RemovedCount} removed",
            distClientDto.ClientId, tenantRepository.TenantId, updates.Count - removedCount, removedCount);
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