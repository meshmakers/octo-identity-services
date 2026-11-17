using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
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
    private readonly MirrorHandlerBackedFacade _facade;
    private readonly ClientMirrorController _sut;

    public ClientMirrorControllerTests()
    {
        _clientStore.TenantId.Returns(ParentTenantId);
        // The write endpoints are facades of the mirror methods; the facade runs the real handlers.
        _facade = new MirrorHandlerBackedFacade(_clientStore, _mirrorService);
        _sut = new ClientMirrorController(_clientStore, _mirrorService, _facade)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
        Arrange(new RtClientBuilder().WithClientId(ClientId).Build());
    }

    /// <summary>The client of the route, as the store and the method target see it.</summary>
    private RtClient Arrange(RtClient client)
    {
        _facade.Know(client);
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);
        return client;
    }

    // ----- POST mirrors/{childTenantId}/secret --------------------

    /// <summary>
    ///     The happy path is the distribution mechanism: the caller gets the plaintext back once,
    ///     because it is unrecoverable afterwards.
    /// </summary>
    [Fact]
    public async Task RotateSecret_ReturnsTheIssuedSecretOnce()
    {
        _mirrorService.RotateMirrorSecretAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns(MirrorSecretRotationResult.Issued("brand-new-secret"));

        var result = await _sut.RotateSecret(ClientId, ChildTenantId);

        var dto = result.Should().BeOfType<OkObjectResult>()
            .Which.Value.Should().BeOfType<MirrorSecretResponseDto>().Subject;
        dto.Secret.Should().Be("brand-new-secret");
        dto.ClientId.Should().Be(ClientId);
        dto.ChildTenantId.Should().Be(ChildTenantId);
    }

    /// <summary>
    ///     🔴 The response DTO carries a live credential, so its <c>ToString</c> must not render it —
    ///     a record's generated <c>ToString</c> prints every property, and any interpolation into a
    ///     log line or exception message would leak the secret.
    /// </summary>
    [Fact]
    public void MirrorSecretResponseDto_ToString_DoesNotRenderTheSecret()
    {
        var dto = new MirrorSecretResponseDto(ClientId, ChildTenantId, "brand-new-secret");

        dto.ToString().Should().NotContain("brand-new-secret");
        dto.ToString().Should().Contain(ClientId);
    }

    /// <summary>Same guarantee one layer down, on the service result.</summary>
    [Fact]
    public void MirrorSecretRotationResult_ToString_DoesNotRenderTheSecret()
    {
        MirrorSecretRotationResult.Issued("brand-new-secret").ToString()
            .Should().NotContain("brand-new-secret");
    }

    [Fact]
    public async Task RotateSecret_UntrackedPair_Returns404()
    {
        _mirrorService.RotateMirrorSecretAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns((MirrorSecretRotationResult?)null);

        var result = await _sut.RotateSecret(ClientId, ChildTenantId);

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task RotateSecret_PublicClient_Returns400()
    {
        _mirrorService.RotateMirrorSecretAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns(MirrorSecretRotationResult.PublicClient());

        var result = await _sut.RotateSecret(ClientId, ChildTenantId);

        result.Should().BeOfType<BadRequestObjectResult>()
            .Which.Value.Should().BeOfType<OperationFailedErrorDto>();
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
        Arrange(client);

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
        Arrange(client);

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
        Arrange(client);
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
        Arrange(client);

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
        Arrange(client);
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

    // ----- the service refuses a child outside the subtree -> 403 ----------------------

    [Fact]
    public async Task ProvisionInTenant_ScopeViolation_Returns403()
    {
        Arrange(new RtClientBuilder().WithClientId(ClientId).WithAutoProvisionInChildTenants().Build());
        _mirrorService.ProvisionInTenantAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns<ClientMirrorProvisioningResult>(_ => throw new ClientMirrorScopeException(ParentTenantId, ChildTenantId));

        (await _sut.ProvisionInTenant(ClientId, ChildTenantId)).Should().BeOfType<ForbidResult>();
    }

    [Fact]
    public async Task RotateSecret_ScopeViolation_Returns403()
    {
        _mirrorService.RotateMirrorSecretAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns<MirrorSecretRotationResult?>(_ => throw new ClientMirrorScopeException(ParentTenantId, ChildTenantId));

        (await _sut.RotateSecret(ClientId, ChildTenantId)).Should().BeOfType<ForbidResult>();
    }

    [Fact]
    public async Task Delete_ScopeViolation_Returns403()
    {
        _mirrorService.RemoveMirrorAsync(ParentTenantId, ClientId, ChildTenantId)
            .Returns<bool>(_ => throw new ClientMirrorScopeException(ParentTenantId, ChildTenantId));

        (await _sut.Delete(ClientId, ChildTenantId)).Should().BeOfType<ForbidResult>();
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
    private readonly MirrorHandlerBackedFacade _facade;
    private readonly ClientAutoProvisionFlagController _sut;
    private readonly List<string> _writes;

    public ClientAutoProvisionFlagControllerTests()
    {
        _writes = ClientStoreMutations.Attach(_clientStore);
        // The endpoint is a facade of Client.SetMirrorAutoProvision; the facade runs the real handler.
        _facade = new MirrorHandlerBackedFacade(_clientStore, Substitute.For<IClientMirrorProvisioningService>());
        _sut = new ClientAutoProvisionFlagController(_clientStore, _facade)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    private RtClient Arrange(RtClient client)
    {
        _facade.Know(client);
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);
        return client;
    }

    [Fact]
    public async Task Set_UnknownClient_Returns404()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(true));

        result.Should().BeOfType<NotFoundObjectResult>();
        _writes.Should().BeEmpty();
    }

    [Fact]
    public async Task Set_FlippingFlag_PersistsViaVersionCheckedMutation()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        Arrange(client);

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(true));

        result.Should().BeOfType<NoContentResult>();
        _writes.Should().Equal(ClientId);
        client.AutoProvisionInChildTenants.Should().BeTrue();
    }

    [Fact]
    public async Task Set_DisablingFlag_StillPersists()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithAutoProvisionInChildTenants()
            .Build();
        Arrange(client);

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(false));

        result.Should().BeOfType<NoContentResult>();
        _writes.Should().Equal(ClientId);
        client.AutoProvisionInChildTenants.Should().BeFalse();
    }

    [Fact]
    public async Task Set_RepeatedConcurrentChanges_Returns409()
    {
        Arrange(new RtClientBuilder().WithClientId(ClientId).Build());
        _clientStore.MutateAsync(ClientId, Arg.Any<Func<RtClient, bool>>())
            .ThrowsAsync(new RtVersionConflictException(new RtEntityId($"System.Identity/Client@{OctoObjectId.GenerateNewId()}"), 1));

        var result = await _sut.Set(ClientId, new SetAutoProvisionInChildTenantsDto(true));

        result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(409);
    }

}
