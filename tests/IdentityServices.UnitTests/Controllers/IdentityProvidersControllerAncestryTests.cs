using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#8339: an OctoTenant identity provider may only name a registry ancestor as its parent. The decision itself is
///     <see cref="ICrossTenantAncestryGuard" />'s (Warn lets through, Enforce refuses); these tests pin that the controller
///     asks it for the tenant the provider is stored in and answers a refusal with 400 and the problem code.
/// </summary>
public sealed class IdentityProvidersControllerAncestryTests : IDisposable
{
    private const string TenantId = "child-tenant";

    private readonly IOctoIdentityProviderStore _store = Substitute.For<IOctoIdentityProviderStore>();
    private readonly ICrossTenantAncestryGuard _guard = Substitute.For<ICrossTenantAncestryGuard>();
    private readonly ServiceProvider _services;
    private readonly IdentityProvidersController _sut;

    public IdentityProvidersControllerAncestryTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<ISecretAttributeProtector>());
        services.AddDynamicAuthentication();
        _services = services.BuildServiceProvider();

        _store.TenantId.Returns(TenantId);
        _sut = new IdentityProvidersController(_store,
            new IdentityProviderDtoMapper(_services.GetRequiredService<IIdentityProviderSecretReader>()),
            Substitute.For<IDistributionEventHubService>(), _guard);
    }

    public void Dispose() => _services.Dispose();

    private static OctoTenantIdentityProviderDto OctoTenantProvider(string parentTenantId) => new()
    {
        Name = $"ParentTenant_{parentTenantId}", IsEnabled = true, ParentTenantId = parentTenantId
    };

    [Fact]
    public async Task Create_ParentNotConfirmedByTheRegistry_Is400WithProblemCode_AndStoresNothing()
    {
        _guard.IsTrustedAncestorAsync(TenantId, "stranger", Arg.Any<string>()).Returns(false);

        var result = await _sut.AddNewIdentityProviderAsync(OctoTenantProvider("stranger"));

        AssertNotAncestorProblem(result.Result, "stranger");
        await _store.DidNotReceiveWithAnyArgs().StoreAsync(default!);
    }

    [Fact]
    public async Task Replace_ParentNotConfirmedByTheRegistry_Is400WithProblemCode_AndStoresNothing()
    {
        _guard.IsTrustedAncestorAsync(TenantId, "stranger", Arg.Any<string>()).Returns(false);

        var result = await _sut.ReplaceProviderAsync(OctoObjectId.GenerateNewId(), OctoTenantProvider("stranger"));

        AssertNotAncestorProblem(result.Result, "stranger");
        await _store.DidNotReceiveWithAnyArgs().StoreAsync(default!);
    }

    [Fact]
    public async Task Replace_DisablingAStoredProviderWithTheSameParent_IsAllowed_WithoutAskingTheGuard()
    {
        var rtId = OctoObjectId.GenerateNewId();
        _store.GetByIdAsync(rtId).Returns(new RtOctoTenantIdentityProvider
            { RtId = rtId, Name = "ParentTenant_stranger", IsEnabled = true, ParentTenantId = "Stranger" });
        var disable = OctoTenantProvider("stranger");
        disable.IsEnabled = false;

        var result = await _sut.ReplaceProviderAsync(rtId, disable);

        result.Result.Should().BeOfType<OkObjectResult>();
        await _store.Received(1).StoreAsync(Arg.Any<RtIdentityProvider>());
        await _guard.DidNotReceiveWithAnyArgs().IsTrustedAncestorAsync(default!, default!, default!);
    }

    [Theory]
    [InlineData("other-stranger", false)]
    [InlineData("stranger", true)]
    public async Task Replace_ChangedParentOrReEnabling_IsStillChecked(string parentTenantId, bool isEnabled)
    {
        var rtId = OctoObjectId.GenerateNewId();
        _store.GetByIdAsync(rtId).Returns(new RtOctoTenantIdentityProvider { RtId = rtId, ParentTenantId = "stranger" });
        _guard.IsTrustedAncestorAsync(TenantId, parentTenantId, Arg.Any<string>()).Returns(false);
        var dto = OctoTenantProvider(parentTenantId);
        dto.IsEnabled = isEnabled;

        var result = await _sut.ReplaceProviderAsync(rtId, dto);

        AssertNotAncestorProblem(result.Result, parentTenantId);
        await _store.DidNotReceiveWithAnyArgs().StoreAsync(default!);
    }

    [Fact]
    public async Task Create_ParentTheGuardAccepts_IsStored()
    {
        _guard.IsTrustedAncestorAsync(TenantId, "parent", Arg.Any<string>()).Returns(true);

        await _sut.AddNewIdentityProviderAsync(OctoTenantProvider("parent"));

        await _store.Received(1).StoreAsync(Arg.Is<RtIdentityProvider>(p =>
            p is RtOctoTenantIdentityProvider && ((RtOctoTenantIdentityProvider)p).ParentTenantId == "parent"));
    }

    [Fact]
    public async Task Create_OtherProviderTypes_DoNotAskTheGuard()
    {
        await _sut.AddNewIdentityProviderAsync(new GoogleIdentityProviderDto
            { Name = "Google", IsEnabled = true, ClientId = "c", ClientSecret = "s" });

        await _guard.DidNotReceiveWithAnyArgs().IsTrustedAncestorAsync(default!, default!, default!);
    }

    private static void AssertNotAncestorProblem(IActionResult? result, string parentTenantId)
    {
        var objectResult = result.Should().BeOfType<ObjectResult>().Subject;
        objectResult.StatusCode.Should().Be(400);
        var problem = objectResult.Value.Should().BeOfType<ProblemDetails>().Subject;
        problem.Extensions["code"].Should().Be(CrossTenantAncestryProblems.ParentTenantNotAncestorCode);
        problem.Detail.Should().Contain(parentTenantId).And.Contain(TenantId);
    }
}
