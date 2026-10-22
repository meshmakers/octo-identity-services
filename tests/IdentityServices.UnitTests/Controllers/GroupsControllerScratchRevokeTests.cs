using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services.ScratchTenants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#7192: removing a client from a group is the revoke of a scratch tenant's creator grant when the group is
///     TenantOwners and the client is the creator's mirror. The controller hands every removal to the grant service,
///     which decides; the removal itself is unchanged.
/// </summary>
public class GroupsControllerScratchRevokeTests
{
    private const string TenantId = "scratchchild";

    private readonly IGroupStore _groupStore = Substitute.For<IGroupStore>();
    private readonly IScratchTenantGrantService _grantService = Substitute.For<IScratchTenantGrantService>();
    private readonly IMultiTenancyResolverService _tenantResolver = Substitute.For<IMultiTenancyResolverService>();
    private readonly GroupsController _sut;

    private readonly OctoObjectId _groupId = OctoObjectId.GenerateNewId();
    private readonly OctoObjectId _clientId = OctoObjectId.GenerateNewId();

    public GroupsControllerScratchRevokeTests()
    {
        _tenantResolver.GetTenantId().Returns(TenantId);
        _groupStore.FindByIdAsync(_groupId).Returns(new RtGroup { RtId = _groupId });
        _sut = new GroupsController(_groupStore, _grantService, _tenantResolver)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    private void SignInAs(params Claim[] claims) =>
        _sut.ControllerContext.HttpContext!.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

    [Fact]
    public async Task RemoveClientMember_RemovesTheMember_ThenOffersTheRemovalToTheGrantService()
    {
        SignInAs(new Claim("preferred_username", "tenant-admin"));

        var result = await _sut.RemoveClientMember(_groupId, _clientId.ToString());

        result.Should().BeOfType<OkResult>();
        await _groupStore.Received(1).RemoveMemberClientAsync(_groupId, _clientId.ToString());
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
        SignInAs(new Claim("preferred_username", "tenant-admin"));
        var unknown = OctoObjectId.GenerateNewId();
        _groupStore.FindByIdAsync(unknown).Returns((RtGroup?)null);

        var result = await _sut.RemoveClientMember(unknown, _clientId.ToString());

        result.Should().BeOfType<NotFoundResult>();
        await _grantService.DidNotReceiveWithAnyArgs()
            .RecordRevocationAsync(default!, default, default, default!);
    }

    [Fact]
    public async Task RemoveClientMember_ANonObjectIdClient_IsStillRemoved_WithoutAskingTheGrantService()
    {
        SignInAs(new Claim("preferred_username", "tenant-admin"));

        var result = await _sut.RemoveClientMember(_groupId, "not-an-object-id");

        result.Should().BeOfType<OkResult>();
        await _groupStore.Received(1).RemoveMemberClientAsync(_groupId, "not-an-object-id");
        await _grantService.DidNotReceiveWithAnyArgs()
            .RecordRevocationAsync(default!, default, default, default!);
    }
}
