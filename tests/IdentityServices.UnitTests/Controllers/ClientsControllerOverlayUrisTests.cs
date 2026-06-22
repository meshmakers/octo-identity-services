using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers.Dto;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     Behavioural pin-down for <c>POST /v1/clients/{id}/overlayUris</c> (AB#4209 Step 4 PR 1).
///     The endpoint is the foundation the octo-cli command + octo-tools cmdlet stack on top of —
///     these tests lock the contract that <c>Source = "overlay:&lt;OverlayName&gt;"</c> is the
///     persisted marker, dedup-by-URI is the conflict rule, and the re-run is a no-op.
/// </summary>
public class ClientsControllerOverlayUrisTests
{
    private const string TenantId = "octosystem";
    private const string ClientId = "octo-data-refinery-studio";
    private const string OverlayName = "local-dev";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly ClientsController _sut;

    public ClientsControllerOverlayUrisTests()
    {
        _clientStore.TenantId.Returns(TenantId);
        _sut = new ClientsController(_clientStore, _eventHub);
    }

    [Fact]
    public async Task ApplyOverlayUris_UnknownClient_Returns404()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:5173/" }
        });

        result.Should().BeOfType<NotFoundObjectResult>();
        await _clientStore.DidNotReceiveWithAnyArgs().UpdateAsync(default!, default!);
    }

    [Fact]
    public async Task ApplyOverlayUris_AllListsEmpty_Returns400_AndDoesNotPersist()
    {
        // Defensive — the endpoint requires at least one URI across the three lists. Without
        // this the caller could no-op-update a client and bump rtChangedDateTime / cache-bust
        // for no reason.
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName
            // all three URI lists null
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        await _clientStore.DidNotReceiveWithAnyArgs().UpdateAsync(default!, default!);
    }

    [Fact]
    public async Task ApplyOverlayUris_AppendsNewEntries_TaggedOverlayPrefixSource()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithRedirectUris("https://studio.example/")    // existing base entry
            .Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/", "https://localhost:5173/" }
        });

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<ApplyOverlayUrisResultDto>().Subject;
        dto.OverlayName.Should().Be(OverlayName);
        dto.ClientId.Should().Be(ClientId);
        dto.RedirectUris.Added.Should().Be(2);
        dto.RedirectUris.SkippedDuplicate.Should().Be(0);

        // The two new entries must carry the overlay-source marker so Step 2a preserves them
        // across blueprint re-apply.
        client.RedirectUris.Should().HaveCount(3);
        client.RedirectUris.Skip(1).Should()
            .OnlyContain(e => e.Source == ClientUriSources.OverlayPrefix + OverlayName);
        client.RedirectUris.Select(e => e.Uri).Should().Equal(
            "https://studio.example/",
            "https://localhost:4200/",
            "https://localhost:5173/");

        await _clientStore.Received(1).UpdateAsync(ClientId, client);
    }

    [Fact]
    public async Task ApplyOverlayUris_DupedAgainstAnySource_SkippedNotDuplicated()
    {
        // Conflict policy: any existing source wins (base / api / overlay:* / family:*),
        // overlay-incoming entry is silently dropped — matches concept doc §4.3.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .Build();
        // Manually add a "base" entry + an "api" entry to prove neither gets duplicated.
        client.RedirectUris.Add(new RtClientUriEntryRecord
            { Uri = "https://studio.example/", Source = ClientUriSources.Base });
        client.RedirectUris.Add(new RtClientUriEntryRecord
            { Uri = "https://operator.example/", Source = ClientUriSources.Api });
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string>
            {
                "https://studio.example/",      // dup-base → skip
                "https://operator.example/",    // dup-api → skip
                "https://localhost:4200/"       // new → append
            }
        });

        var dto = (result as OkObjectResult)!.Value as ApplyOverlayUrisResultDto;
        dto!.RedirectUris.Added.Should().Be(1);
        dto.RedirectUris.SkippedDuplicate.Should().Be(2);
        client.RedirectUris.Should().HaveCount(3);
    }

    [Fact]
    public async Task ApplyOverlayUris_IsIdempotent_OnSecondCallSameInput()
    {
        // The cmdlet may run on every Start-Octo or every CI pipeline. Re-applying the same
        // overlay must be a no-op (Added=0 across the board) — no DB churn, no log noise.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithRedirectUris("https://studio.example/")
            .Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var dto = new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/" }
        };

        var first = (await _sut.ApplyOverlayUris(ClientId, dto)) as OkObjectResult;
        var second = (await _sut.ApplyOverlayUris(ClientId, dto)) as OkObjectResult;

        var firstDto = first!.Value as ApplyOverlayUrisResultDto;
        var secondDto = second!.Value as ApplyOverlayUrisResultDto;
        firstDto!.RedirectUris.Added.Should().Be(1);
        secondDto!.RedirectUris.Added.Should().Be(0);
        secondDto.RedirectUris.SkippedDuplicate.Should().Be(1);
        // List doesn't grow past the seeded + first-apply state.
        client.RedirectUris.Should().HaveCount(2);
    }

    [Fact]
    public async Task ApplyOverlayUris_AppliesToAllThreeListsIndependently()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/" },
            PostLogoutRedirectUris = new List<string> { "https://localhost:4200/" },
            AllowedCorsOrigins = new List<string> { "https://localhost:4200" }
        });

        var dto = (result as OkObjectResult)!.Value as ApplyOverlayUrisResultDto;
        dto!.RedirectUris.Added.Should().Be(1);
        dto.PostLogoutRedirectUris.Added.Should().Be(1);
        dto.AllowedCorsOrigins.Added.Should().Be(1);

        var overlaySource = ClientUriSources.OverlayPrefix + OverlayName;
        client.RedirectUris.Single().Source.Should().Be(overlaySource);
        client.PostLogoutRedirectUris.Single().Source.Should().Be(overlaySource);
        client.AllowedCorsOrigins.Single().Source.Should().Be(overlaySource);
    }

    [Fact]
    public async Task ApplyOverlayUris_SkipsWhitespaceOnlyInputUris()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/", "   ", "" }
        });

        var dto = (result as OkObjectResult)!.Value as ApplyOverlayUrisResultDto;
        dto!.RedirectUris.Added.Should().Be(1);
        client.RedirectUris.Should().HaveCount(1);
        client.RedirectUris.Single().Uri.Should().Be("https://localhost:4200/");
    }
}
