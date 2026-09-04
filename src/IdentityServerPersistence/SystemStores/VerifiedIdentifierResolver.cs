using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     CK-backed implementation of <see cref="IVerifiedIdentifierResolver" /> over the
///     <c>System.Identity/VerifiedExternalIdentifier</c> entity and its <c>IdentifiesUser</c> edge
///     (AB#5122). Same tenant-resolution idiom as <see cref="ExternalTenantUserMappingStore" /> and
///     <see cref="ClientImpersonationStore" />: the repository is resolved lazily per call so
///     construction before the inline middleware wired the tenant is safe.
/// </summary>
public class VerifiedIdentifierResolver(
    IMultiTenancyResolverService multiTenancyResolverService,
    ILogger<VerifiedIdentifierResolver> logger) : IVerifiedIdentifierResolver
{
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task<VerifiedIdentifierResolution?> ResolveAsync(
        RtIdentifierKindEnum identifierKind,
        string identifierValue,
        RtTrustLevelEnum messageTrust)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var binding = await FindBindingAsync(session, identifierKind, identifierValue);
        if (binding == null)
        {
            await session.CommitTransactionAsync();
            return null;
        }

        var user = await GetBoundUserAsync(session, binding);
        await session.CommitTransactionAsync();

        if (user == null)
        {
            // Dangling binding (its user was removed) — treat as not-found rather than resolving to
            // a phantom identity.
            logger.LogWarning(
                "VerifiedExternalIdentifier '{BindingRtId}' ({Kind}) in tenant '{TenantId}' has no bound user; treating as not-found",
                binding.RtId, identifierKind, TenantRepository.TenantId);
            return null;
        }

        var enrollmentTrust = binding.EnrollmentTrust;
        var effectiveTrust = TrustLevels.Min(enrollmentTrust, messageTrust);

        return new VerifiedIdentifierResolution(
            user,
            binding.RtId,
            enrollmentTrust,
            messageTrust,
            effectiveTrust);
    }

    public async Task<OctoObjectId> StoreBindingAsync(VerifiedIdentifierBinding binding)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Unknown user is rejected — the directory never records a binding to a phantom identity.
        var user = await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, binding.UserRtId);
        if (user == null)
        {
            await session.CommitTransactionAsync();
            throw new NotExistingException($"User '{binding.UserRtId}' does not exist.");
        }

        var now = DateTime.UtcNow;
        var existing = await FindBindingAsync(session, binding.IdentifierKind, binding.IdentifierValue);

        if (existing == null)
        {
            // Insert the entity and its mandatory IdentifiesUser edge in one change set — the graph
            // rule engine requires entity and (multiplicity-One) edge together (see DataPermissionStore).
            var entity = new RtVerifiedExternalIdentifier
            {
                RtId = OctoObjectId.GenerateNewId(),
                IdentifierKind = binding.IdentifierKind,
                IdentifierValue = binding.IdentifierValue,
                EnrollmentTrust = binding.EnrollmentTrust,
                RequiredMessageAuthentication = binding.RequiredMessageAuthentication,
                Source = binding.Source,
                EnrolledAt = binding.EnrolledAt ?? now,
                LastVerifiedAt = binding.LastVerifiedAt ?? now
            };

            var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
            var operationResult = new OperationResult();
            await TenantRepository.ApplyChangesAsync(session,
                new List<IEntityUpdateInfo<RtEntity>> { EntityUpdateInfo<RtEntity>.CreateInsert(entity) },
                new List<AssociationUpdateInfo>
                {
                    AssociationUpdateInfo.CreateInsert(
                        entity.ToRtEntityId(),
                        new RtEntityId(userCkTypeId, binding.UserRtId),
                        IdentityAssociationConstants.IdentifiesUserId)
                }, operationResult);
            await session.CommitTransactionAsync();

            logger.LogInformation(
                "Created verified identifier binding {Kind}/{BindingRtId} → user '{UserRtId}' (enrollmentTrust={Trust}) in tenant '{TenantId}'",
                binding.IdentifierKind, entity.RtId, binding.UserRtId, binding.EnrollmentTrust,
                TenantRepository.TenantId);
            return entity.RtId;
        }

        // Idempotent upsert of the single row for this (kind, value): refresh attributes and, when
        // the user changed, re-point the IdentifiesUser edge — keeping the uniqueness invariant.
        existing.EnrollmentTrust = binding.EnrollmentTrust;
        existing.RequiredMessageAuthentication = binding.RequiredMessageAuthentication;
        existing.Source = binding.Source;
        existing.EnrolledAt = existing.EnrolledAt ?? binding.EnrolledAt ?? now;
        existing.LastVerifiedAt = binding.LastVerifiedAt ?? now;
        await TenantRepository.ReplaceOneRtEntityByIdAsync(session, existing.RtId, existing);

        var currentUserRtId = await GetBoundUserRtIdAsync(session, existing);
        if (currentUserRtId != binding.UserRtId)
        {
            var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
            var updates = new List<AssociationUpdateInfo>();
            if (currentUserRtId != null)
            {
                updates.Add(AssociationUpdateInfo.CreateDelete(
                    existing.ToRtEntityId(),
                    new RtEntityId(userCkTypeId, currentUserRtId.Value),
                    IdentityAssociationConstants.IdentifiesUserId));
            }

            updates.Add(AssociationUpdateInfo.CreateInsert(
                existing.ToRtEntityId(),
                new RtEntityId(userCkTypeId, binding.UserRtId),
                IdentityAssociationConstants.IdentifiesUserId));

            var operationResult = new OperationResult();
            await TenantRepository.ApplyChangesAsync(session, updates, operationResult);
        }

        await session.CommitTransactionAsync();

        logger.LogInformation(
            "Updated verified identifier binding {Kind}/{BindingRtId} → user '{UserRtId}' (enrollmentTrust={Trust}) in tenant '{TenantId}'",
            binding.IdentifierKind, existing.RtId, binding.UserRtId, binding.EnrollmentTrust,
            TenantRepository.TenantId);
        return existing.RtId;
    }

    public async Task<bool> RemoveBindingAsync(RtIdentifierKindEnum identifierKind, string identifierValue)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existing = await FindBindingAsync(session, identifierKind, identifierValue);
        if (existing == null)
        {
            await session.CommitTransactionAsync();
            return false;
        }

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtVerifiedExternalIdentifier>(
            session, existing.RtId, DeleteOptions.Erase);
        await session.CommitTransactionAsync();

        logger.LogInformation(
            "Removed verified identifier binding {Kind}/{BindingRtId} in tenant '{TenantId}'",
            identifierKind, existing.RtId, TenantRepository.TenantId);
        return true;
    }

    /// <summary>
    ///     Finds the single binding for a (kind, value). Queries on the highly selective
    ///     <c>IdentifierValue</c> and disambiguates the kind in memory — the (kind, value) pair is
    ///     unique per tenant (enforced by the Unique CK index), so at most one row survives.
    /// </summary>
    private async Task<RtVerifiedExternalIdentifier?> FindBindingAsync(
        IOctoSession session, RtIdentifierKindEnum identifierKind, string identifierValue)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtVerifiedExternalIdentifier.IdentifierValue), identifierValue);

        var result = await TenantRepository
            .GetRtEntitiesByTypeAsync<RtVerifiedExternalIdentifier>(session, queryOptions);

        return result.Items.SingleOrDefault(e => e.IdentifierKind == identifierKind);
    }

    private async Task<OctoObjectId?> GetBoundUserRtIdAsync(
        IOctoSession session, RtVerifiedExternalIdentifier binding)
    {
        var associations = await TenantRepository.GetRtAssociationsAsync(
            session,
            binding.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.IdentifiesUserId));

        return associations.Items.SingleOrDefault()?.TargetRtId;
    }

    private async Task<RtUser?> GetBoundUserAsync(
        IOctoSession session, RtVerifiedExternalIdentifier binding)
    {
        var userRtId = await GetBoundUserRtIdAsync(session, binding);
        return userRtId == null
            ? null
            : await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, userRtId.Value);
    }
}
