using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

public class BlueprintClientUriPreservationTests
{
    private const string OverlayLocalDev = "overlay:local-dev";
    private static readonly OctoObjectId BlueprintRtIdRefineryStudio = new("660000000000000000000030");
    private static readonly OctoObjectId BlueprintRtIdMcpDevice = new("660000000000000000000034");
    private static readonly OctoObjectId OperatorRtId = new("6a3527cf39424fc1460f66f1");

    [Fact]
    public void Capture_FiltersBaseSourcedEntries_KeepsOnlyApiAndOverlay()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("https://operator.example/", ClientUriSources.Api),
                ("http://localhost:4200/", OverlayLocalDev),
            });

        var capture = BlueprintClientUriPreservation.Capture(new[] { client });

        capture.Should().ContainKey(BlueprintRtIdRefineryStudio);
        var entry = capture[BlueprintRtIdRefineryStudio];
        entry.RedirectUris.Should().HaveCount(2);
        entry.RedirectUris.Select(e => e.Uri).Should()
            .Equal("https://operator.example/", "http://localhost:4200/");
        entry.RedirectUris.Select(e => e.Source).Should()
            .Equal(ClientUriSources.Api, OverlayLocalDev);
    }

    [Fact]
    public void Capture_SkipsOperatorCreatedClients_OutsideBlueprintRtIdRange()
    {
        // Operator-created clients (rtId outside 660…00..660…FF range) are owned by the operator
        // and untouched by the blueprint apply. Preservation does NOT apply to them.
        var client = CreateClient(
            rtId: OperatorRtId,
            clientId: "operator-custom-client",
            redirectUris: new[]
            {
                ("https://op.example/", ClientUriSources.Api),
            });

        var capture = BlueprintClientUriPreservation.Capture(new[] { client });

        capture.Should().BeEmpty();
    }

    [Fact]
    public void Capture_SkipsBlueprintClient_WithOnlyBaseEntries()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
            });

        var capture = BlueprintClientUriPreservation.Capture(new[] { client });

        // No non-base entries → no capture row. The post-apply restore is a fast read-and-skip.
        capture.Should().BeEmpty();
    }

    [Fact]
    public void Capture_HandlesEmptyUriLists()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdMcpDevice,
            clientId: "octo-mcpServices-device",
            redirectUris: Array.Empty<(string, string)>());

        var capture = BlueprintClientUriPreservation.Capture(new[] { client });

        capture.Should().BeEmpty();
    }

    [Fact]
    public void Capture_RecognisesNonBaseInEachOfTheThreeLists()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://operator.example/", ClientUriSources.Api),
            },
            postLogoutRedirectUris: new[]
            {
                ("https://operator.example/post-logout/", ClientUriSources.Api),
            },
            allowedCorsOrigins: new[]
            {
                ("https://operator.example", OverlayLocalDev),
            });

        var capture = BlueprintClientUriPreservation.Capture(new[] { client });

        var entry = capture.Should().ContainKey(BlueprintRtIdRefineryStudio).WhoseValue;
        entry.RedirectUris.Should().HaveCount(1);
        entry.PostLogoutRedirectUris.Should().HaveCount(1);
        entry.AllowedCorsOrigins.Should().HaveCount(1);
    }

    [Fact]
    public void Merge_AppendsNonBaseEntries_NotPresentInPostApplyList()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
            });

        var capture = new NonBaseUriCapture(
            BlueprintRtIdRefineryStudio,
            "octo-data-refinery-studio",
            RedirectUris: new[]
            {
                Entry("https://operator.example/", ClientUriSources.Api),
                Entry("http://localhost:4200/", OverlayLocalDev),
            },
            PostLogoutRedirectUris: Array.Empty<RtClientUriEntryRecord>(),
            AllowedCorsOrigins: Array.Empty<RtClientUriEntryRecord>());

        var mutated = BlueprintClientUriPreservation.Merge(client, capture);

        mutated.Should().BeTrue();
        client.RedirectUris.Should().HaveCount(3);
        client.RedirectUris.Select(e => e.Uri).Should()
            .Equal("https://studio.example/", "https://operator.example/", "http://localhost:4200/");
        client.RedirectUris.Select(e => e.Source).Should()
            .Equal(ClientUriSources.Base, ClientUriSources.Api, OverlayLocalDev);
    }

    [Fact]
    public void Merge_SkipsCapturedEntryWhenSeedReassertsSameUri_SeedWins()
    {
        // After the apply the seed now declares "https://operator.example/" as a "base" entry too
        // (an operator-suggested URI got promoted into the canonical seed). The captured copy is
        // dropped — base wins on URI collisions.
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("https://operator.example/", ClientUriSources.Base),
            });

        var capture = new NonBaseUriCapture(
            BlueprintRtIdRefineryStudio,
            "octo-data-refinery-studio",
            RedirectUris: new[]
            {
                Entry("https://operator.example/", ClientUriSources.Api),
            },
            PostLogoutRedirectUris: Array.Empty<RtClientUriEntryRecord>(),
            AllowedCorsOrigins: Array.Empty<RtClientUriEntryRecord>());

        var mutated = BlueprintClientUriPreservation.Merge(client, capture);

        mutated.Should().BeFalse();
        client.RedirectUris.Should().HaveCount(2);
        client.RedirectUris.Last().Source.Should().Be(ClientUriSources.Base);
    }

    [Fact]
    public void Merge_IsIdempotent_OnSecondRunWithSameCapture()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
            });

        var capture = new NonBaseUriCapture(
            BlueprintRtIdRefineryStudio,
            "octo-data-refinery-studio",
            RedirectUris: new[]
            {
                Entry("https://operator.example/", ClientUriSources.Api),
            },
            PostLogoutRedirectUris: Array.Empty<RtClientUriEntryRecord>(),
            AllowedCorsOrigins: Array.Empty<RtClientUriEntryRecord>());

        var firstMutated = BlueprintClientUriPreservation.Merge(client, capture);
        var secondMutated = BlueprintClientUriPreservation.Merge(client, capture);

        firstMutated.Should().BeTrue();
        secondMutated.Should().BeFalse();
        client.RedirectUris.Should().HaveCount(2);
    }

    [Fact]
    public void Merge_AppliesToEachOfTheThreeListsIndependently()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: Array.Empty<(string, string)>(),
            postLogoutRedirectUris: Array.Empty<(string, string)>(),
            allowedCorsOrigins: Array.Empty<(string, string)>());

        var capture = new NonBaseUriCapture(
            BlueprintRtIdRefineryStudio,
            "octo-data-refinery-studio",
            RedirectUris: new[] { Entry("https://r.example/", ClientUriSources.Api) },
            PostLogoutRedirectUris: new[] { Entry("https://p.example/", ClientUriSources.Api) },
            AllowedCorsOrigins: new[] { Entry("https://c.example", ClientUriSources.Api) });

        var mutated = BlueprintClientUriPreservation.Merge(client, capture);

        mutated.Should().BeTrue();
        client.RedirectUris.Should().ContainSingle(e => e.Uri == "https://r.example/");
        client.PostLogoutRedirectUris.Should().ContainSingle(e => e.Uri == "https://p.example/");
        client.AllowedCorsOrigins.Should().ContainSingle(e => e.Uri == "https://c.example");
    }

    private static RtClient CreateClient(
        OctoObjectId rtId,
        string clientId,
        IEnumerable<(string Uri, string Source)> redirectUris,
        IEnumerable<(string Uri, string Source)>? postLogoutRedirectUris = null,
        IEnumerable<(string Uri, string Source)>? allowedCorsOrigins = null)
    {
        var client = new RtClient
        {
            RtId = rtId,
            ClientId = clientId,
            RedirectUris = ToRecordList(redirectUris),
            PostLogoutRedirectUris = ToRecordList(
                postLogoutRedirectUris ?? Array.Empty<(string, string)>()),
            AllowedCorsOrigins = ToRecordList(
                allowedCorsOrigins ?? Array.Empty<(string, string)>())
        };
        return client;
    }

    private static AttributeRecordValueList<RtClientUriEntryRecord> ToRecordList(
        IEnumerable<(string Uri, string Source)> entries)
    {
        var list = new AttributeRecordValueList<RtClientUriEntryRecord>();
        foreach (var (uri, source) in entries)
        {
            list.Add(Entry(uri, source));
        }
        return list;
    }

    private static RtClientUriEntryRecord Entry(string uri, string source) =>
        new() { Uri = uri, Source = source };
}
