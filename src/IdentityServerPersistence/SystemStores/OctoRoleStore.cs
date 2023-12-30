using System.Security.Claims;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.Infrastructure.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repository;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public sealed class OctoRoleStore :
    IQueryableRoleStore<RtRole>,
    IRoleClaimStore<RtRole>
{
    private readonly ITenantRepository _tenantRepository;
    private bool _disposed;

    public OctoRoleStore(IMultiTenancyResolverService multiTenancyResolverService, IdentityErrorDescriber? describer)
    {
        _tenantRepository = multiTenancyResolverService.GetTenantRepository();
        ErrorDescriber = describer ?? new IdentityErrorDescriber();
        Roles = _tenantRepository.AsQueryable<RtRole>();
    }

    public IdentityErrorDescriber ErrorDescriber { get; }

    public async Task<IdentityResult> CreateAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        await _tenantRepository.InsertOneRtEntityAsync(session, role).ConfigureAwait(false);

        await session.CommitTransactionAsync();

        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        var currentConcurrencyStamp = role != null ? role.ConcurrencyStamp : throw new ArgumentNullException(nameof(role));
        role.ConcurrencyStamp = Guid.NewGuid().ToString();

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        var fieldFilters = new List<FieldFilter>
        {
            new(nameof(RtRole.ConcurrencyStamp), FieldFilterOperator.Equals, currentConcurrencyStamp)
        };

        try
        {
            await _tenantRepository.ReplaceOneRtEntityAsync(session, fieldFilters, role).ConfigureAwait(false);
            await session.CommitTransactionAsync();
            return IdentityResult.Success;
        }
        catch (PersistenceException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
    }

    public async Task<IdentityResult> DeleteAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        List<FieldFilter> fieldFilters = new()
        {
            new FieldFilter(nameof(RtRole.ConcurrencyStamp), FieldFilterOperator.Equals, role.ConcurrencyStamp),
            new FieldFilter(nameof(RtRole.RtId), FieldFilterOperator.Equals, role.RtId)
        };

        try
        {
            await _tenantRepository.DeleteOneRtEntityAsync<RtRole>(session, fieldFilters).ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
            return IdentityResult.Success;
        }
        catch (PersistenceException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
    }

    public Task<string> GetRoleIdAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return role != null ? Task.FromResult(ConvertIdToString(role.RtId)) : throw new ArgumentNullException(nameof(role));
    }

    public Task<string?> GetRoleNameAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return role != null ? Task.FromResult(role.Name) : throw new ArgumentNullException(nameof(role));
    }

    public Task SetRoleNameAsync(RtRole role, string? roleName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);

        role.Name = roleName;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedRoleNameAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return role != null ? Task.FromResult(role.NormalizedName) : throw new ArgumentNullException(nameof(role));
    }

    public Task SetNormalizedRoleNameAsync(
        RtRole role,
        string? normalizedRoleName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);

        role.NormalizedName = normalizedRoleName;
        return Task.CompletedTask;
    }

    public async Task<RtRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        var result = await _tenantRepository.GetRtEntityByRtIdAsync<RtRole>(session, ConvertIdFromString(roleId)).ConfigureAwait(false);
        await session.CommitTransactionAsync().ConfigureAwait(false);
        return result;
    }

    public async Task<RtRole?> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, normalizedName);

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, dataQueryOperation);

        await session.CommitTransactionAsync();
        return result.Items.FirstOrDefault();
    }

    public void Dispose()
    {
        _disposed = true;
    }

    public IQueryable<RtRole> Roles { get; }

    public async Task<IList<Claim>> GetClaimsAsync(RtRole role, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);

        var dbRole = await FindByIdAsync(ConvertIdToString(role.RtId), cancellationToken).ConfigureAwait(false);
        if (dbRole == null) throw NotExistingException.RoleWithIdDoesNotExist(role.RtId);

        return dbRole.Claims?.Select(e => new Claim(e.ClaimType, e.ClaimValue)).ToList() ?? new List<Claim>();
    }

    public async Task AddClaimAsync(RtRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);
        ArgumentValidation.Validate(nameof(claim), claim);

        var rtRoleClaimRecord = new RtRoleClaimRecord
        {
            ClaimType = claim.Type,
            ClaimValue = claim.Value
        };

        role.Claims ??= new AttributeRecordValueList<RtRoleClaimRecord>();
        role.Claims.Add(rtRoleClaimRecord);

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, role.RtId, role).ConfigureAwait(false);
        await session.CommitTransactionAsync();
    }

    public async Task RemoveClaimAsync(RtRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(role), role);
        ArgumentValidation.Validate(nameof(claim), claim);

        role.Claims?.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);

        using var session = await _tenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, role.RtId, role).ConfigureAwait(false);

        await session.CommitTransactionAsync();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(GetType().Name);
    }

    private OctoObjectId ConvertIdFromString(string id)
    {
        return new OctoObjectId(id);
    }

    private string ConvertIdToString(OctoObjectId id)
    {
        return id.ToString();
    }
}