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
///     keeps it on an existing user. AB#7772 (System.Identity 2.28.0, ckLanguage 2): the same attributes are
///     <c>access: Hidden</c> (UserName and Email <c>MethodOnly</c>, AccessFailedCount and LockoutEnd
///     <c>ReadOnly</c>), so an <c>ImportRt</c> can no longer carry them (OCTO-CK139) - the identity service
///     writes them through its own repository, which these tests use to create the users. Real MongoDB and the real System.Identity model of this repository; the
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
        await InsertUserAsync(repo, rtId, firstName: "Ada");
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
        await InsertUserAsync(repo, rtId, firstName: "Ada");

        // A blueprint re-apply imports the seed (no credential material, no UserName/Email: MethodOnly) with
        // the Upsert strategy.
        await ImportAsync(repo, UserSeed(rtId, firstName: "Ada v2"), ImportStrategy.Upsert);

        var updated = await LoadUserAsync(repo, rtId);
        updated.PasswordHash.Should().Be(FakeHash);
        updated.SecurityStamp.Should().Be(FakeStamp);
        updated.UserTokens.Should().ContainSingle().Which.Value.Should().Be(FakeTokenValue);
        // Control: the import really replaced the entity.
        updated.FirstName.Should().Be("Ada v2");
    }

    [Fact]
    public async Task CompiledModel_AccessModifiers_CloseTheGenericReadAndWritePath()
    {
        var repo = await GetRepositoryAsync();
        var user = await repo.GetCkTypeGraphAsync(RtEntityExtensions.GetRtCkTypeId<RtUser>());

        var expected = new Dictionary<string, CkAttributeAccessDto>
        {
            ["PasswordHash"] = CkAttributeAccessDto.Hidden,
            ["SecurityStamp"] = CkAttributeAccessDto.Hidden,
            ["UserTokens"] = CkAttributeAccessDto.Hidden,
            ["AccessFailedCount"] = CkAttributeAccessDto.ReadOnly,
            ["LockoutEnd"] = CkAttributeAccessDto.ReadOnly,
            ["UserName"] = CkAttributeAccessDto.MethodOnly,
            ["Email"] = CkAttributeAccessDto.MethodOnly,
            // Untouched: still read and written like before.
            ["FirstName"] = CkAttributeAccessDto.ReadWrite,
            ["TwoFactorEnabled"] = CkAttributeAccessDto.ReadWrite,
            ["LockoutEnabled"] = CkAttributeAccessDto.ReadWrite
        };
        foreach (var (name, access) in expected)
        {
            var attribute = user.AllAttributes.Values.Single(a => a.AttributeName == name);
            attribute.Access.Should().Be(access, name);
            attribute.IsReadableOutsideMethod.Should().Be(access != CkAttributeAccessDto.Hidden, name);
            attribute.IsWritableOutsideMethod.Should().Be(
                access is CkAttributeAccessDto.ReadWrite or CkAttributeAccessDto.ReadOnly, name);
        }

        // ConcurrencyStamp is not part of this model (nothing to hide).
        user.AllAttributes.Values.Should().NotContain(a => a.AttributeName == "ConcurrencyStamp");
    }

    [Theory]
    [InlineData("PasswordHash", "value: test-not-a-real-password-hash")]
    [InlineData("SecurityStamp", "value: TESTNOTAREALSECURITYSTAMP")]
    [InlineData("UserName", "value: someone")]
    [InlineData("Email", "value: someone@example.test")]
    public async Task ImportRt_OfAHiddenOrMethodOnlyUserAttribute_IsRefusedWithCk139_AndWritesNothing(
        string attribute, string value)
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();

        var act = () => ImportAsync(repo,
            UserSeed(rtId, "Ada", $"\n      - id: System.Identity/{attribute}\n        {value}"),
            ImportStrategy.Upsert);

        var exception = (await act.Should().ThrowAsync<ExchangeException>()).Which;
        exception.MessageNumber.Should().Be(139, "OCTO-CK139: only a CK method may write the attribute");
        exception.Message.Should().Contain(attribute);
        (await FindUserAsync(repo, rtId)).Should().BeNull("a refused import writes nothing");
    }

    [Fact]
    public async Task ImportRt_OfAReadOnlyUserAttribute_StaysPossible()
    {
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();

        await ImportAsync(repo,
            UserSeed(rtId, "Ada", "\n      - id: System.Identity/AccessFailedCount\n        value: 2"),
            ImportStrategy.Upsert);

        (await LoadUserAsync(repo, rtId)).AccessFailedCount.Should().Be(2);
    }

    [Fact]
    public async Task IdentityRepositoryWrites_OfHiddenMethodOnlyAndReadOnlyAttributes_StillWork()
    {
        // The identity service writes these through its own repository (sign-in counters, lockout, password
        // change, user provisioning); the access modifiers guard the generic paths, not this one.
        var repo = await GetRepositoryAsync();
        var rtId = OctoObjectId.GenerateNewId();
        await InsertUserAsync(repo, rtId, "Ada");

        using (var session = await repo.GetSessionAsync())
        {
            session.StartTransaction();
            var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
            user!.PasswordHash = "test-not-a-real-password-hash-2";
            user.SecurityStamp = "TESTNOTAREALSECURITYSTAMP2";
            user.AccessFailedCount = 3;
            user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5);
            user.Email = "changed@example.test";
            user.UserName = "changed-user";
            await repo.ReplaceOneRtEntityByIdAsync(session, rtId, user);
            await session.CommitTransactionAsync();
        }

        var reloaded = await LoadUserAsync(repo, rtId);
        reloaded.PasswordHash.Should().Be("test-not-a-real-password-hash-2");
        reloaded.SecurityStamp.Should().Be("TESTNOTAREALSECURITYSTAMP2");
        reloaded.AccessFailedCount.Should().Be(3);
        reloaded.LockoutEnd.Should().NotBeNull();
        reloaded.Email.Should().Be("changed@example.test");
        reloaded.UserName.Should().Be("changed-user");
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

    private static async Task<RtUser?> FindUserAsync(ITenantRepository repo, OctoObjectId rtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var entity = await repo.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
        await session.CommitTransactionAsync();
        return entity;
    }

    private static async Task<RtUser> LoadUserAsync(ITenantRepository repo, OctoObjectId rtId) =>
        await FindUserAsync(repo, rtId) ?? throw new InvalidOperationException($"User {rtId} was not created.");

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

    // The way the identity service creates a user: through its own repository (no import, no access guard).
    private static async Task InsertUserAsync(ITenantRepository repo, OctoObjectId rtId, string firstName)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = rtId,
            UserName = $"user-{rtId}",
            Email = $"user-{rtId}@example.test",
            FirstName = firstName,
            LastName = "Lovelace",
            EmailConfirmed = true,
            PhoneNumberConfirmed = false,
            TwoFactorEnabled = true,
            PasswordHash = FakeHash,
            SecurityStamp = FakeStamp,
            UserTokens = new AttributeRecordValueList<RtUserTokenRecord>
            {
                new RtUserTokenRecord
                {
                    LoginProvider = "[AspNetUserStore]",
                    Name = "AuthenticatorKey",
                    UserId = rtId.ToString(),
                    Value = FakeTokenValue
                }
            }
        });
        await session.CommitTransactionAsync();
    }

    private static string UserSeed(OctoObjectId rtId, string firstName, string extraAttributes = "") =>
        $"""
            $schema: https://schemas.meshmakers.cloud/runtime-model.schema.json
            dependencies:
              - System.Identity-2.28.0
            entities:
              - rtId: '{rtId}'
                ckTypeId: System.Identity/User
                attributes:
                  - id: System.Identity/FirstName
                    value: {firstName}
                  - id: System.Identity/LastName
                    value: Lovelace
                  - id: System.Identity/EmailConfirmed
                    value: true
                  - id: System.Identity/PhoneNumberConfirmed
                    value: false
                  - id: System.Identity/TwoFactorEnabled
                    value: true{extraAttributes}
            """;
}
