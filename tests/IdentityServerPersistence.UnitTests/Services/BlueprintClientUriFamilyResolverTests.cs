using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

public class BlueprintClientUriFamilyResolverTests
{
    private static readonly OctoObjectId BlueprintRtIdRefineryStudio = new("660000000000000000000030");
    private static readonly OctoObjectId BlueprintRtIdMcpDevice = new("660000000000000000000034");
    private static readonly OctoObjectId OperatorRtId = new("6a3527cf39424fc1460f66f1");

    [Theory]
    [InlineData("{{family.local-dev}}", "local-dev")]
    [InlineData("{{family.LOCAL-DEV}}", "LOCAL-DEV")]
    [InlineData("{{family.a.b.c_d-e}}", "a.b.c_d-e")]
    [InlineData("  {{family.local-dev}}  ", "local-dev")]
    [InlineData("{{ family.local-dev }}", "local-dev")]
    public void TryParseFamilyName_RecognisesPlaceholderShape(string uri, string expected)
    {
        BlueprintClientUriFamilyResolver.TryParseFamilyName(uri).Should().Be(expected);
    }

    [Theory]
    [InlineData("http://localhost:4200/")]
    [InlineData("{{family.x}}/suffix")]
    [InlineData("prefix/{{family.x}}")]
    [InlineData("${octo.identity.refineryStudioUrl}")]
    [InlineData("")]
    [InlineData("{{ notFamily.x }}")]
    [InlineData("{family.x}")]
    public void TryParseFamilyName_RejectsNonPlaceholders(string uri)
    {
        BlueprintClientUriFamilyResolver.TryParseFamilyName(uri).Should().BeNull();
    }

    [Theory]
    [InlineData("https://localhost:5173/", "CorsOrigin", "https://localhost:5173")]
    [InlineData("https://localhost:5173", "CorsOrigin", "https://localhost:5173")]
    [InlineData("https://localhost:5173/", "RedirectUri", "https://localhost:5173/")]
    [InlineData("https://localhost:5173/", "PostLogoutRedirectUri", "https://localhost:5173/")]
    [InlineData("https://localhost:5173///", "CorsOrigin", "https://localhost:5173")]
    public void NormaliseForList_StripsTrailingSlashOnlyForCorsOrigin(
        string input, string kindName, string expected)
    {
        var kind = Enum.Parse<UriListKind>(kindName);
        BlueprintClientUriFamilyResolver.NormaliseForList(input, kind).Should().Be(expected);
    }

    // ---- Fresh-seed-apply path (placeholder present in list) ----------------------------------

    [Fact]
    public void Reconcile_FreshApply_ReplacesPlaceholder_WithAllFamilyMembers()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("{{family.local-dev}}", ClientUriSources.Base),
            });

        var families = Families(("local-dev", "http://localhost:4200/", "http://localhost:5173/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(3);
        result.RedirectUris.Select(e => e.Uri).Should().Equal(
            "https://studio.example/",
            "http://localhost:4200/",
            "http://localhost:5173/");
        result.RedirectUris.Select(e => e.Source).Should().Equal(
            ClientUriSources.Base,
            "family:local-dev",
            "family:local-dev");
    }

    [Fact]
    public void Reconcile_FreshApply_DropsPlaceholder_WhenFamilyUnconfigured()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("{{family.local-dev}}", ClientUriSources.Base),
            });

        var result = BlueprintClientUriFamilyResolver.Reconcile(
            new[] { client },
            new Dictionary<string, IReadOnlyList<string>>())
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(1);
        result.RedirectUris.Single().Uri.Should().Be("https://studio.example/");
    }

    [Fact]
    public void Reconcile_FreshApply_DropsPlaceholder_WhenFamilyMembersListIsEmpty()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("{{family.local-dev}}", ClientUriSources.Base),
            });

        var families = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["local-dev"] = Array.Empty<string>(),
        };

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().BeEmpty();
    }

    [Fact]
    public void Reconcile_DropsWhitespaceOnlyFamilyMembers()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("{{family.local-dev}}", ClientUriSources.Base),
            });

        var families = Families(("local-dev", "http://localhost:4200/", "   ", "http://localhost:5173/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(2);
        result.RedirectUris.Select(e => e.Uri).Should().Equal(
            "http://localhost:4200/",
            "http://localhost:5173/");
    }

    [Fact]
    public void Reconcile_FamilyNameMatchIsCaseInsensitive()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("{{family.LOCAL-DEV}}", ClientUriSources.Base),
            });

        var families = Families(("local-dev", "http://localhost:4200/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(1);
        result.RedirectUris.Single().Source.Should().Be("family:LOCAL-DEV");
    }

    [Fact]
    public void Reconcile_SkipsClient_WithNoPlaceholderAndNoExistingFamilyEntries()
    {
        // The 4 currently-non-family-seeded blueprint clients (660…31..34) land here every
        // restart. Without a signal in the DB the reconciler skips them with no DB write.
        var client = CreateClient(
            rtId: BlueprintRtIdMcpDevice,
            clientId: "octo-mcpServices-device",
            redirectUris: new[]
            {
                ("https://mcp.example/", ClientUriSources.Base),
            });

        var families = Families(("local-dev", "http://localhost:4200/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families);

        result.Should().BeEmpty();
    }

    [Fact]
    public void Reconcile_SkipsOperatorCreatedClients_OutsideBlueprintRtIdRange()
    {
        var client = CreateClient(
            rtId: OperatorRtId,
            clientId: "operator-custom-client",
            redirectUris: new[]
            {
                ("{{family.local-dev}}", ClientUriSources.Base),
            });

        var families = Families(("local-dev", "http://localhost:4200/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families);

        result.Should().BeEmpty();
    }

    [Fact]
    public void Reconcile_ResolvesPlaceholders_InAllThreeUriListsIndependently()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[] { ("{{family.local-dev}}", ClientUriSources.Base) },
            postLogoutRedirectUris: new[] { ("{{family.local-dev}}", ClientUriSources.Base) },
            allowedCorsOrigins: new[] { ("{{family.local-dev}}", ClientUriSources.Base) });

        var families = Families(("local-dev", "https://localhost:5173/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Select(e => e.Uri).Should().Equal("https://localhost:5173/");
        result.PostLogoutRedirectUris.Select(e => e.Uri).Should().Equal("https://localhost:5173/");
        // CORS normalised: trailing slash stripped so IdentityServer's ValidatingClientStore
        // doesn't reject the entire client config.
        result.AllowedCorsOrigins.Select(e => e.Uri).Should().Equal("https://localhost:5173");
    }

    // ---- Reconciliation path (no placeholder, existing family entries) ------------------------

    [Fact]
    public void Reconcile_ReplacesExistingFamilyEntries_WithCurrentConfigMembers()
    {
        // Subsequent restart where the engine didn't re-import the seed. DB still carries
        // family entries from a previous expansion. Env config has changed — the reconciler
        // brings the DB back into sync.
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("http://localhost:4200/", "family:local-dev"),     // stale member
                ("http://localhost:5173/", "family:local-dev"),     // still in config
            });

        var families = Families(("local-dev", "http://localhost:5173/", "http://localhost:5180/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(3);
        result.RedirectUris.Select(e => e.Uri).Should().Equal(
            "https://studio.example/",
            "http://localhost:5173/",
            "http://localhost:5180/");
        result.RedirectUris.Skip(1).Should()
            .OnlyContain(e => e.Source == "family:local-dev");
    }

    [Fact]
    public void Reconcile_RemovesAllFamilyEntries_WhenFamilyRemovedFromConfig()
    {
        // Operator removed every member of `local-dev` from env config. After restart the DB
        // should mirror that change — no manual cleanup required by the contract.
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("http://localhost:4200/", "family:local-dev"),
                ("http://localhost:5173/", "family:local-dev"),
            });

        var result = BlueprintClientUriFamilyResolver.Reconcile(
            new[] { client },
            new Dictionary<string, IReadOnlyList<string>>())
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(1);
        result.RedirectUris.Single().Uri.Should().Be("https://studio.example/");
        result.RedirectUris.Single().Source.Should().Be(ClientUriSources.Base);
    }

    [Fact]
    public void Reconcile_NoChange_WhenDbAlreadyMatchesCurrentConfig()
    {
        // Idempotent: a restart with no config drift produces an empty result so the
        // orchestrator skips the DB write round-trip.
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("http://localhost:5173/", "family:local-dev"),
            });

        var families = Families(("local-dev", "http://localhost:5173/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families);

        result.Should().BeEmpty();
    }

    [Fact]
    public void Reconcile_HandlesMultipleFamilyNamesOnSameList()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("{{family.local-dev}}", ClientUriSources.Base),
                ("http://qa-runner.example/", "family:qa-runners"),
            });

        var families = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["local-dev"] = new[] { "http://localhost:4200/" },
            ["qa-runners"] = new[] { "http://qa-runner.example/" },
        };

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(3);
        var uris = result.RedirectUris.Select(e => (e.Uri, e.Source)).ToList();
        uris.Should().Contain(("https://studio.example/", ClientUriSources.Base));
        uris.Should().Contain(("http://localhost:4200/", "family:local-dev"));
        uris.Should().Contain(("http://qa-runner.example/", "family:qa-runners"));
    }

    [Fact]
    public void Reconcile_PreservesNonFamilyEntries_DuringReconciliation()
    {
        // base, api, overlay:* sources are not touched by the reconciler — only family:*
        // entries (and matching {{family.NAME}} placeholders) participate.
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("https://operator.example/", ClientUriSources.Api),
                ("https://overlay.example/", ClientUriSources.OverlayPrefix + "local-dev"),
                ("http://stale.example/", "family:local-dev"),
            });

        var families = Families(("local-dev", "http://localhost:4200/"));

        var result = BlueprintClientUriFamilyResolver.Reconcile(new[] { client }, families)
            [BlueprintRtIdRefineryStudio];

        result.RedirectUris.Should().HaveCount(4);
        var uris = result.RedirectUris.Select(e => (e.Uri, e.Source)).ToList();
        uris.Should().Contain(("https://studio.example/", ClientUriSources.Base));
        uris.Should().Contain(("https://operator.example/", ClientUriSources.Api));
        uris.Should().Contain(("https://overlay.example/", ClientUriSources.OverlayPrefix + "local-dev"));
        uris.Should().Contain(("http://localhost:4200/", "family:local-dev"));
        uris.Should().NotContain(e => e.Uri == "http://stale.example/");
    }

    [Fact]
    public void ApplyToClient_ReplacesListContents()
    {
        var client = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("{{family.local-dev}}", ClientUriSources.Base),
            });

        var reconciliation = BlueprintClientUriFamilyResolver.Reconcile(
            new[] { client },
            Families(("local-dev", "http://localhost:4200/", "http://localhost:5173/")))
            [BlueprintRtIdRefineryStudio];

        // Fresh post-apply client matching the reconciler's source state. ApplyToClient
        // replaces each list with the reconciled contents.
        var postApply = CreateClient(
            rtId: BlueprintRtIdRefineryStudio,
            clientId: "octo-data-refinery-studio",
            redirectUris: new[]
            {
                ("https://studio.example/", ClientUriSources.Base),
                ("{{family.local-dev}}", ClientUriSources.Base),
            });
        BlueprintClientUriFamilyResolver.ApplyToClient(postApply, reconciliation);

        postApply.RedirectUris.Should().HaveCount(3);
        postApply.RedirectUris.Select(e => e.Uri).Should().Equal(
            "https://studio.example/",
            "http://localhost:4200/",
            "http://localhost:5173/");
        postApply.RedirectUris.Skip(1).Select(e => e.Source).Should().AllBe("family:local-dev");
    }

    // ---- Helpers -------------------------------------------------------------------------------

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> Families(
        params (string Name, string Member1, string? Member2, string? Member3)[] families)
    {
        var dict = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, m1, m2, m3) in families)
        {
            var members = new List<string> { m1 };
            if (m2 != null) members.Add(m2);
            if (m3 != null) members.Add(m3);
            dict[name] = members;
        }
        return dict;
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> Families(
        params (string Name, string Member1, string? Member2)[] families)
    {
        var dict = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, m1, m2) in families)
        {
            var members = new List<string> { m1 };
            if (m2 != null) members.Add(m2);
            dict[name] = members;
        }
        return dict;
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> Families(
        params (string Name, string Member1)[] families)
    {
        var dict = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, m1) in families)
        {
            dict[name] = new[] { m1 };
        }
        return dict;
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
            list.Add(new RtClientUriEntryRecord { Uri = uri, Source = source });
        }
        return list;
    }
}
