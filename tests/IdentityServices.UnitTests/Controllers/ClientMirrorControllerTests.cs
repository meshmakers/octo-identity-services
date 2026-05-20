using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
/// Behavioural pin-down for the new mirror-management endpoints (#4045). Coverage is
/// the controller layer's branching (404 / 400 / OK / NoContent), not the underlying
/// provisioning logic — that lives in IClientMirrorProvisioningService unit tests.
/// </summary>
public class ClientMirrorControllerTests
{
    private const string ParentTenantId = "octosystem";
    private const string ClientId = "ci-deploy";
    private const string ChildTenantId = "acme";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IClientMirrorProvisioningService _mirrorService =
        Substitute.For<IClientMirrorProvisioningService>();
    private readonly ClientMirrorController _sut;

    public ClientMirrorControllerTests()
    {
        _clientStore.TenantId.Returns(ParentTenantId);
        _sut = new ClientMirrorController(_clientStore, _mirrorService);
    }

    // ----- GET mirrors -----------------------------------------------------

    [Fact]
    public async Task Get_UnknownClient_Returns404()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.Get(ClientId);

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task Get_ReturnsMirrorsAsDtos()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId(ClientId)
            .WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId)
            .WithSecretHashVersion(2)
            .Build();
        _mirrorService.GetMirrorsAsync(ParentTenantId, ClientId)
            .Returns(new[] { mirror });

        var result = await _sut.Get(ClientId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dtos = ok.Value.Should().BeAssignableTo<IEnumerable<ClientMirrorDto>>().Subject.ToList();
        dtos.Should().ContainSingle();
        dtos[0].ParentClientId.Should().Be(ClientId);
        dtos[0].ChildTenantId.Should().Be(ChildTenantId);
        dtos[0].SecretHashVersion.Should().Be(2);
    }

    // ----- POST provisionInExistingTenants ---------------------------------

    [Fact]
    public async Task ProvisionInExistingTenants_UnknownClient_Returns404()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.ProvisionInExistingTenants(ClientId);

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task ProvisionInExistingTenants_NotFlagged_Returns400()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        // AutoProvisionInChildTenants defaults to false.
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ProvisionInExistingTenants(ClientId);

        result.Should().BeOfType<BadRequestObjectResult>();
        await _mirrorService.DidNotReceiveWithAnyArgs()
            .ProvisionForAllChildTenantsAsync(default!, default!);
    }

    [Fact]
    public async Task ProvisionInExistingTenants_Flagged_DelegatesAndReturnsCounts()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithAutoProvisionInChildTenants()
            .Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);
        _mirrorService.ProvisionForAllChildTenantsAsync(ParentTenantId, ClientId)
            .Returns(new ClientMirrorBackfillResult(3, 2, 1));

        var result = await _sut.ProvisionInExistingTenants(ClientId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value.Should().BeOfType<ClientMirrorBackfillResponseDto>().Subject;
        body.ChildTenantsConsidered.Should().Be(3);
        body.NewlyProvisioned.Should().Be(2);
        body.AlreadyPresent.Should().Be(1);
    }

    // ----- POST provisionInTenant ------------------------------------------

    [Fact]
    public async Task ProvisionInTenant_NotFlagged_Returns400()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ProvisionInTenant(ClientId, ChildTenantId);

        result.Should().BeOfType<BadRequestObjectResult>();
        await _mirrorService.DidNotReceiveWithAnyArgs()
            .ProvisionInTenantAsync(default!, default!, default!);
    }

    [Fact]
    public async Task ProvisionInTenant_Flagged_DelegatesAndReturnsCounts()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithAutoProvisionInChildTenants()
            .Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);
        _mirrorService.ProvisionInTenantAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns(new ClientMirrorProvisioningResult(1, 1, 0));

        var result = await _sut.ProvisionInTenant(ClientId, ChildTenantId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<ClientMirrorProvisionResponseDto>()
            .Which.NewlyProvisioned.Should().Be(1);
    }

    // ----- DELETE one mirror -----------------------------------------------

    [Fact]
    public async Task Delete_NoMirrorTracked_Returns404()
    {
        _mirrorService.RemoveMirrorAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns(false);

        var result = await _sut.Delete(ClientId, ChildTenantId);

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task Delete_MirrorRemoved_Returns204()
    {
        _mirrorService.RemoveMirrorAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns(true);

        var result = await _sut.Delete(ClientId, ChildTenantId);

        result.Should().BeOfType<NoContentResult>();
    }
}

/// <summary>
/// PATCH on the auto-provision flag is split into its own controller for routing
/// hygiene (separate sub-resource), so it gets its own test class.
/// </summary>
public class ClientAutoProvisionFlagControllerTests
{
    private const string ClientId = "ci-deploy";
    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly ClientAutoProvisionFlagController _sut;

    public ClientAutoProvisionFlagControllerTests()
    {
        _sut = new ClientAutoProvisionFlagController(_clientStore);
    }

    [Fact]
    public async Task Set_UnknownClient_Returns404()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(true));

        result.Should().BeOfType<NotFoundObjectResult>();
        await _clientStore.DidNotReceiveWithAnyArgs().UpdateAsync(default!, default!);
    }

    [Fact]
    public async Task Set_FlippingFlag_PersistsViaUpdateAsync()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(true));

        result.Should().BeOfType<NoContentResult>();
        await _clientStore.Received(1).UpdateAsync(
            ClientId,
            Arg.Is<RtClient>(c => c.AutoProvisionInChildTenants == true));
    }

    [Fact]
    public async Task Set_DisablingFlag_StillPersists()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithAutoProvisionInChildTenants()
            .Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(false));

        result.Should().BeOfType<NoContentResult>();
        await _clientStore.Received(1).UpdateAsync(
            ClientId,
            Arg.Is<RtClient>(c => c.AutoProvisionInChildTenants == false));
    }
}
