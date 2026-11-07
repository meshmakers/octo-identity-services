using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#8437: <c>DELETE AdminProvisioning/{targetTenantId}/{mappingRtId}</c> reads the mapping's group names only for the
///     <c>Identity.CrossTenantGrantRemoved</c> audit event. A failing read must not break the deletion (AB#8342 AC 3).
/// </summary>
public class AdminProvisioningDeleteAuditTests
{
    private const string Target = "target";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRepository _repository = Substitute.For<ITenantRepository>();
    private readonly ICrossTenantGrantAuditRecorder _audit = Substitute.For<ICrossTenantGrantAuditRecorder>();
    private readonly RtExternalTenantUserMapping _mapping = new()
    {
        RtId = OctoObjectId.GenerateNewId(), SourceTenantId = "source", SourceUserId = "u1", SourceUserName = "alice"
    };

    public AdminProvisioningDeleteAuditTests()
    {
        _systemContext.TryFindTenantRepositoryAsync(Target).Returns(_repository);
        _repository.GetSessionAsync().Returns(_ => Substitute.For<IOctoSession>());
        _repository.GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(Arg.Any<IOctoSession>(), _mapping.RtId)
            .Returns(_mapping);
    }

    [Fact]
    public async Task Delete_WhenTheAuditGroupReadFails_StillDeletesCommitsAndRecordsTheRemovalWithoutGroups()
    {
        _repository.GetRtAssociationsAsync(Arg.Any<IOctoSession>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtAssociationExtendedQueryOptions>())
            .ThrowsAsync(new InvalidOperationException("association read failed"));

        var result = await Controller().Delete(Target, _mapping.RtId);

        result.Should().BeOfType<OkResult>();
        await _repository.Received(1).DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(
            Arg.Any<IOctoSession>(), _mapping.RtId, DeleteOptions.Erase);
        await _audit.Received(1).RecordGrantAsync(CrossTenantGrantAuditEvents.GrantRemoved, Target,
            Arg.Any<string>(), _mapping, Arg.Is<IReadOnlyList<string>>(g => g.Count == 0));
    }

    [Fact]
    public async Task Delete_WhenTheAuditSessionCannotBeOpened_StillDeletes()
    {
        // The first session (the delete transaction) opens; the second one, for the audit read, fails.
        var deleteSession = Substitute.For<IOctoSession>();
        _repository.GetSessionAsync().Returns(Task.FromResult(deleteSession),
            Task.FromException<IOctoSession>(new InvalidOperationException("no session")));

        var result = await Controller().Delete(Target, _mapping.RtId);

        result.Should().BeOfType<OkResult>();
        await _repository.Received(1).DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(deleteSession,
            _mapping.RtId, DeleteOptions.Erase);
        await deleteSession.Received(1).CommitTransactionAsync();
    }

    private AdminProvisioningController Controller() => new(_systemContext,
        Substitute.For<IDynamicAuthSchemeService>(), Substitute.For<ICrossTenantShadowUserChainResolver>(),
        Substitute.For<ICrossTenantAncestryGuard>(), _audit, NullLogger<AdminProvisioningController>.Instance)
    {
        ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
    };
}
