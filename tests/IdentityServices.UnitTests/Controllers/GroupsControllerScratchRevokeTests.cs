using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services.ScratchTenants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#7192: removing a client from a group is the revoke of a scratch tenant's creator grant when the group is
///     TenantOwners and the client is the creator's mirror. The endpoint is a facade of <c>Group.RemoveMember</c>; the
///     handler (run here behind the controller) hands every removal to the grant service, which decides; the removal itself
///     is unchanged. The revoker is the caller's subject (a client-credentials caller: its client id).
/// </summary>
public class GroupsControllerScratchRevokeTests
{
    private const string TenantId = "scratchchild";

    private readonly IGroupStore _groupStore = Substitute.For<IGroupStore>();
    private readonly IScratchTenantGrantService _grantService = Substitute.For<IScratchTenantGrantService>();
    private readonly IMultiTenancyResolverService _tenantResolver = Substitute.For<IMultiTenancyResolverService>();
    private readonly ITenantRepository _repository = Substitute.For<ITenantRepository>();
    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly GroupsController _sut;

    private readonly OctoObjectId _groupId = OctoObjectId.GenerateNewId();
    private readonly OctoObjectId _clientId = OctoObjectId.GenerateNewId();

    public GroupsControllerScratchRevokeTests()
    {
        _tenantResolver.GetTenantId().Returns(TenantId);
        _tenantResolver.GetTenantRepository().Returns(_repository);
        _groupStore.FindByIdAsync(_groupId).Returns(new RtGroup { RtId = _groupId });
        _repository.GetRtEntityByRtIdAsync<RtClient>(Arg.Any<IOctoSession>(), _clientId)
            .Returns(new RtClient { RtId = _clientId, ClientId = "agent-mirror" });
        _clientStore.FindRtClientByIdAsync("agent-mirror")
            .Returns(new RtClient { RtId = _clientId, ClientId = "agent-mirror" });
        _groupStore.GetMemberClientIdsAsync(_groupId).Returns([_clientId.ToString()]);
        var methods = new HandlerBackedMethodFacade(_clientStore, groupStore: _groupStore, grantService: _grantService,
            tenantResolver: _tenantResolver);
        _sut = new GroupsController(_groupStore, Substitute.For<IRoleChangeRefusals>(),
            methods, Substitute.For<RoleManager<RtRole>>(Substitute.For<IRoleStore<RtRole>>(), null, null, null, null))
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    private void SignInAs(params Claim[] claims) =>
        _sut.ControllerContext.HttpContext!.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

    [Fact]
    public async Task RemoveClientMember_RemovesTheMember_ThenOffersTheRemovalToTheGrantService()
    {
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));

        var result = await _sut.RemoveClientMember(_groupId, _clientId.ToString());

        result.Should().BeOfType<OkResult>();
        await _groupStore.Received(1).RemoveMemberClientAsync(_groupId, _clientId.ToString());
        await _grantService.Received(1).RecordRevocationAsync(TenantId, _groupId, _clientId, "tenant-admin");
    }

    [Fact]
    public async Task RemoveClientMember_RecordsTheRevoke_BeforeTheMembershipIsRemoved()
    {
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));

        await _sut.RemoveClientMember(_groupId, _clientId.ToString());

        Received.InOrder(() =>
        {
            _grantService.RecordRevocationAsync(TenantId, _groupId, _clientId, "tenant-admin");
            _groupStore.RemoveMemberClientAsync(_groupId, _clientId.ToString());
        });
    }

    [Fact]
    public async Task RemoveClientMember_WhenTheRemovalFails_TheRevokeIsAlreadyPersisted()
    {
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));
        _groupStore.RemoveMemberClientAsync(_groupId, _clientId.ToString())
            .Returns(Task.FromException(new InvalidOperationException("db down")));

        var result = await _sut.RemoveClientMember(_groupId, _clientId.ToString());

        result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);

        await _grantService.Received(1).RecordRevocationAsync(TenantId, _groupId, _clientId, "tenant-admin");
    }

    [Fact]
    public async Task RemoveClientMember_ByAServiceToken_NamesTheClientAsTheRevoker()
    {
        SignInAs(new Claim("client_id", "agent-client"));

        await _sut.RemoveClientMember(_groupId, _clientId.ToString());

        await _grantService.Received(1).RecordRevocationAsync(TenantId, _groupId, _clientId, "agent-client");
    }

    [Fact]
    public async Task RemoveClientMember_UnknownGroup_Is404_AndRevokesNothing()
    {
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));
        var unknown = OctoObjectId.GenerateNewId();
        _groupStore.FindByIdAsync(unknown).Returns((RtGroup?)null);

        var result = await _sut.RemoveClientMember(unknown, _clientId.ToString());

        result.Should().BeOfType<NotFoundResult>();
        await _grantService.DidNotReceiveWithAnyArgs()
            .RecordRevocationAsync(default!, default, default, default!);
    }

    [Fact]
    public async Task RemoveClientMember_ByClientId_RemovesTheClientsRtId_AndOffersTheRevoke()
    {
        // AB#8571: the OAuth client id names the same client as its rtId.
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));

        var result = await _sut.RemoveClientMember(_groupId, "agent-mirror");

        result.Should().BeOfType<OkResult>();
        await _groupStore.Received(1).RemoveMemberClientAsync(_groupId, _clientId.ToString());
        await _grantService.Received(1).RecordRevocationAsync(TenantId, _groupId, _clientId, "tenant-admin");
    }

    [Fact]
    public async Task RemoveClientMember_TheRtIdOfADeletedClient_StillRemovesTheLeftoverEdge()
    {
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));
        var deleted = OctoObjectId.GenerateNewId();
        _groupStore.GetMemberClientIdsAsync(_groupId).Returns([_clientId.ToString(), deleted.ToString()]);

        var result = await _sut.RemoveClientMember(_groupId, deleted.ToString());

        result.Should().BeOfType<OkResult>();
        await _groupStore.Received(1).RemoveMemberClientAsync(_groupId, deleted.ToString());
    }

    [Fact]
    public async Task RemoveClientMember_AnUnknownClientId_Is404_AndChangesNothing()
    {
        SignInAs(new Claim("sub", "tenant-admin"), new Claim("preferred_username", "admin"));

        var result = await _sut.RemoveClientMember(_groupId, "no-such-client");

        result.Should().BeOfType<NotFoundObjectResult>()
            .Which.Value.Should().BeOfType<NotFoundErrorDto>();
        await _groupStore.DidNotReceiveWithAnyArgs().RemoveMemberClientAsync(default, default!);
        await _grantService.DidNotReceiveWithAnyArgs()
            .RecordRevocationAsync(default!, default, default, default!);
    }
}
