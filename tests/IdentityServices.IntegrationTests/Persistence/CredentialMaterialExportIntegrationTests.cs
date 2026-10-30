using FluentAssertions;

using IdentityServices.IntegrationTests.Fixtures;

using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts.DependencyGraph;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.TransportContainer;
using Meshmakers.Octo.Runtime.Contracts.TransportContainer.DTOs;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#7766 (audit finding H3, System.Identity 2.27.0): the credential material of a user - password hash,
///     security stamp and the authenticator tokens (TOTP key, recovery codes) - is <c>ownership: Secret</c>.
///     An <c>ExportRt</c> (export as template, tenant clone) never carries it, and a blueprint re-apply (Upsert)
///     keeps it on an existing user. Real MongoDB and the real System.Identity model of this repository; the
///     converter is the one the export jobs of octo-bot-services use for both the by-query and the deep-graph
///     export. All values are synthetic.
/// </summary>
[Collection("Sequential")]
public class CredentialMaterialExportIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string FakeHash = "test-not-a-real-password-hash";
    private const string FakeStamp = "TESTNOTAREALSECURITYSTAMP";
    private const string FakeTokenValue = "test-not-a-real-totp-key";

    private static readonly string[] CredentialAttributes = ["PasswordHash", "SecurityStamp", "UserTokens"];

    private readonly IdentityServicesFixture _fixture;

    public CredentialMaterialExportIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task CompiledModel_CredentialMaterialIsSecret_AndEverythingElseIsStillExported()
    {
        var repo = await GetRepositoryAsync();
        var user = await repo.GetCkTypeGraphAsync(RtEntityExtensions.GetRtCkTypeId<RtUser>());

        foreach (var attribute in CredentialAttributes)
        {
            Ownership(user, attribute).Should().Be(AttributeOwnershipDto.Secret, attribute);
            Ownership(user, attribute).IsExcludedFromExport().Should().BeTrue(attribute);
        }

        foreach (var attribute in new[] { "UserName", "Email", "FirstName", "LastName", "PhoneNumber", "TwoFactorEnabled" })
        {
            Ownership(user, attribute).IsExcludedFromExport().Should().BeFalse(
                $"{attribute} is part of the portable user definition");
        }

        // The record member that holds the authenticator key / recovery codes: a copy of the record
        // elsewhere never exports it either.
        var token = _fixture.GetService<ICkCacheService>().GetRtCkRecord(
            _fixture.GetSystemContext().TenantId, new RtCkId<CkRecordId>("System.Identity/UserToken"));
        token.AllAttributes.Values.Single(a => a.AttributeName == "Value").Ownership
            .Should().Be(AttributeOwnershipDto.Secret);
    }

    [Fact]
    public async Task Export_OfAUserWithPasswordAndTwoFactorTokens_CarriesNoCredentialMaterial()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, UserSeed(rtId, withCredentials: true, firstName: "Ada"), ImportStrategy.Upsert);
        var user = await LoadUserAsync(repo, rtId);
        user.PasswordHash.Should().Be(FakeHash, "control: the user really holds the credential material");
        user.UserTokens.Should().ContainSingle();

        // Same converter call as ExportRtModelByQueryCommand and ExportRtModelByDeepGraphCommand.
        var dto = _fixture.GetService<IRtEntityToTcDtoConverter>()
            .Convert(_fixture.GetSystemContext().TenantId, user);

        var exported = dto.Attributes.Select(a => a.Id.ToString()).ToList();
        foreach (var attribute in CredentialAttributes)
        {
            exported.Should().NotContain($"System.Identity/{attribute}");
        }

        exported.Should().Contain(["System.Identity/UserName", "System.Identity/Email", "System.Identity/FirstName",
            "System.Identity/LastName", "System.Identity/TwoFactorEnabled", "System.Identity/EmailConfirmed"],
            "all other user attributes are exported");
        dto.Attributes.Single(a => a.Id.ToString() == "System.Identity/FirstName").Value.Should().Be("Ada");

        // Nothing of the credential values anywhere in the exported attributes.
        var serialized = System.Text.Json.JsonSerializer.Serialize(dto.Attributes.Select(a => a.Value));
        serialized.Should().NotContain(FakeHash).And.NotContain(FakeStamp).And.NotContain(FakeTokenValue);
    }

    [Fact]
    public async Task Upsert_OfTheSeedShapedUser_KeepsPasswordHashSecurityStampAndTokens()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await ImportAsync(repo, UserSeed(rtId, withCredentials: true, firstName: "Ada"), ImportStrategy.Upsert);

        // A blueprint re-apply imports the seed (no credential material) with the Upsert strategy.
        await ImportAsync(repo, UserSeed(rtId, withCredentials: false, firstName: "Ada v2"), ImportStrategy.Upsert);

        var updated = await LoadUserAsync(repo, rtId);
        updated.PasswordHash.Should().Be(FakeHash);
        updated.SecurityStamp.Should().Be(FakeStamp);
        updated.UserTokens.Should().ContainSingle().Which.Value.Should().Be(FakeTokenValue);
        // Control: the import really replaced the entity.
        updated.FirstName.Should().Be("Ada v2");
    }

    [Fact]
    public async Task BootstrapBlueprintSeed_DoesNotSeedUsers()
    {
        // The re-apply guarantee above is about users a blueprint could ever touch; the shipped bootstrap
        // blueprint seeds none (users are created by the product), so nothing of it can reset a hash.
        var seedDir = FindRepoFile("src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data");
        foreach (var file in Directory.EnumerateFiles(seedDir, "*.yaml", SearchOption.AllDirectories))
        {
            (await File.ReadAllTextAsync(file, TestContext.Current.CancellationToken))
                .Should().NotContain("ckTypeId: System.Identity/User\n", file)
                .And.NotContain("ckTypeId: System.Identity/User\r\n", file);
        }
    }

    private static AttributeOwnershipDto Ownership(CkTypeWithAttributesGraph graph, string attributeName) =>
        graph.AllAttributes.Values
            .Single(a => a.AttributeName.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
            .Ownership;

    private async Task<ITenantRepository> GetRepositoryAsync()
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>()
            .SetupAsync(_fixture.GetSystemContext().TenantId);
        return _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
    }

    private async Task ImportAsync(ITenantRepository repo, string yaml, ImportStrategy strategy) =>
        await _fixture.GetService<IImportRtModelCommand>().ImportTextAsync(repo, yaml, strategy);

    private static async Task<RtUser> LoadUserAsync(ITenantRepository repo, OctoObjectId rtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var entity = await repo.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
        await session.CommitTransactionAsync();
        return entity ?? throw new InvalidOperationException($"User {rtId} was not imported.");
    }

    private static string FindRepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Octo.Identity.sln")))
        {
            dir = dir.Parent;
        }

        return dir == null
            ? throw new FileNotFoundException("Octo.Identity.sln not found above the test binaries.")
            : Path.Combine(dir.FullName, relativePath);
    }

    private static string UserSeed(OctoObjectId rtId, bool withCredentials, string firstName)
    {
        var credentials = withCredentials
            ? $"""

                  - id: System.Identity/PasswordHash
                    value: {FakeHash}
                  - id: System.Identity/SecurityStamp
                    value: {FakeStamp}
                  - id: System.Identity/UserTokens
                    value:
                      - ckRecordId: System.Identity/UserToken
                        attributes:
                          - id: System.Identity/LoginProvider
                            value: '[AspNetUserStore]'
                          - id: System/Name
                            value: AuthenticatorKey
                          - id: System.Identity/UserId
                            value: '{rtId}'
                          - id: System.Identity/Value
                            value: {FakeTokenValue}
            """
            : string.Empty;

        return $"""
            $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
            dependencies:
              - System.Identity-2.27.0
            entities:
              - rtId: '{rtId}'
                ckTypeId: System.Identity/User
                attributes:
                  - id: System.Identity/UserName
                    value: user-{rtId}
                  - id: System.Identity/Email
                    value: user-{rtId}@example.test
                  - id: System.Identity/FirstName
                    value: {firstName}
                  - id: System.Identity/LastName
                    value: Lovelace
                  - id: System.Identity/EmailConfirmed
                    value: true
                  - id: System.Identity/PhoneNumberConfirmed
                    value: false
                  - id: System.Identity/TwoFactorEnabled
                    value: true{credentials}
            """;
    }
}
