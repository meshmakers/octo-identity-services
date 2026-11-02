using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores.OpenIddict;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Infrastructure.Services;
using IdentityServerPersistence;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#7765: the revocation that runs after a password change is tenant-scoped. The same subject id
///     in two tenants (a user mirrored into a child tenant) keeps its tokens in the other tenant when the
///     password is changed in one of them. Real MongoDB, real tenant databases.
/// </summary>
public class PasswordChangeRevocationTenantIsolationIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public PasswordChangeRevocationTenantIsolationIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task RevokeBySubject_InOneTenant_LeavesTheSameSubjectsTokensAndAuthorizationsInTheOtherTenant()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var childTenantId = $"revk-{Guid.NewGuid():N}"[..20];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        await setup.SetupAsync(childTenantId);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var systemRepo = (await systemContext.TryFindTenantRepositoryAsync(systemContext.TenantId))!;

        var subject = OctoObjectId.GenerateNewId().ToString();
        var childTokens = new OpenIddictTokenStore(new FixedTenantResolver(childRepo));
        var systemTokens = new OpenIddictTokenStore(new FixedTenantResolver(systemRepo));
        var childAuthorizations = new OpenIddictAuthorizationStore(new FixedTenantResolver(childRepo));
        var systemAuthorizations = new OpenIddictAuthorizationStore(new FixedTenantResolver(systemRepo));
        var ct = TestContext.Current.CancellationToken;

        foreach (var (tokens, authorizations) in new[] { (childTokens, childAuthorizations), (systemTokens, systemAuthorizations) })
        {
            var token = await tokens.InstantiateAsync(ct);
            token.SubjectId = subject;
            token.ClientId = "client";
            token.TokenType = "refresh_token";
            token.Status = "valid";
            token.CreationDateTime = DateTime.UtcNow;
            token.ExpirationDateTime = DateTime.UtcNow.AddDays(30);
            await tokens.CreateAsync(token, ct);

            var authorization = await authorizations.InstantiateAsync(ct);
            authorization.SubjectId = subject;
            authorization.ClientId = "client";
            authorization.Status = "valid";
            authorization.CreationDateTime = DateTime.UtcNow;
            await authorizations.SetScopesAsync(authorization, System.Collections.Immutable.ImmutableArray.Create("openid"), ct);
            await authorizations.CreateAsync(authorization, ct);
        }

        (await childTokens.RevokeBySubjectAsync(subject, ct)).Should().Be(1);
        (await childAuthorizations.RevokeBySubjectAsync(subject, ct)).Should().Be(1);

        (await CountValidTokensAsync(childTokens, subject, ct)).Should().Be(0);
        (await CountValidAuthorizationsAsync(childAuthorizations, subject, ct)).Should().Be(0);
        (await CountValidTokensAsync(systemTokens, subject, ct)).Should().Be(1, "the other tenant is untouched");
        (await CountValidAuthorizationsAsync(systemAuthorizations, subject, ct)).Should().Be(1);
    }

    private static async Task<int> CountValidTokensAsync(IOpenIddictTokenStore<RtOAuthToken> store, string subject,
        CancellationToken ct)
    {
        var count = 0;
        await foreach (var token in store.FindBySubjectAsync(subject, ct))
        {
            if (token.Status == "valid")
            {
                count++;
            }
        }

        return count;
    }

    private static async Task<int> CountValidAuthorizationsAsync(
        IOpenIddictAuthorizationStore<RtOAuthAuthorization> store, string subject, CancellationToken ct)
    {
        var count = 0;
        await foreach (var authorization in store.FindBySubjectAsync(subject, ct))
        {
            if (authorization.Status == "valid")
            {
                count++;
            }
        }

        return count;
    }
}
