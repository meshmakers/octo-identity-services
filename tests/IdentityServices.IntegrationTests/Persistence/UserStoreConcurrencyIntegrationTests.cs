using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#7770 (finding L9) against a real MongoDB (Testcontainers): the account lockout counts every failed sign-in
///     even when sign-ins run in parallel, and a concurrent change of one user is reported as a concurrency failure
///     instead of overwriting the other writer. Every simulated request gets its own <see cref="UserManager{TUser}" />
///     and store, as in a real request scope; the tests assert final state, never retry counts.
/// </summary>
public class UserStoreConcurrencyIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public UserStoreConcurrencyIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ParallelFailedSignIns_AreAllCounted_RepeatedTwentyTimes()
    {
        var repo = await CreateTenantRepositoryAsync();
        const int attempts = 10;

        for (var round = 0; round < 20; round++)
        {
            var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 1000);

            await RunInParallelAsync(attempts, async () =>
            {
                var manager = CreateUserManager(repo, maxFailedAccessAttempts: 1000);
                var user = (await manager.FindByNameAsync(userName))!;
                await manager.AccessFailedAsync(user);
            });

            var stored = await FindAsync(repo, userName);
            stored.AccessFailedCount.Should().Be(attempts, $"round {round}: no failed sign-in may be lost");
            stored.LockoutEnd.Should().BeNull("the threshold was not reached");
        }
    }

    [Fact]
    public async Task ParallelFailedSignIns_ReturnDistinctCounts()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 1000);
        var counts = new System.Collections.Concurrent.ConcurrentBag<int>();

        await RunInParallelAsync(10, async () =>
        {
            var store = CreateUserStore(repo);
            var user = (await store.FindByNameAsync(userName.ToUpperInvariant()))!;
            counts.Add(await store.IncrementAccessFailedCountAsync(user));
        });

        counts.OrderBy(c => c).Should().Equal(Enumerable.Range(1, 10),
            "each failed attempt gets its own count, none is lost or counted twice");
    }

    [Fact]
    public async Task ParallelFailedSignIns_LockTheAccountAtTheConfiguredThreshold_RepeatedTwentyTimes()
    {
        var repo = await CreateTenantRepositoryAsync();

        for (var round = 0; round < 20; round++)
        {
            var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

            await RunInParallelAsync(10, async () =>
            {
                var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
                var user = (await manager.FindByNameAsync(userName))!;
                await manager.AccessFailedAsync(user);
            });

            var stored = await FindAsync(repo, userName);
            stored.LockoutEnd.Should().NotBeNull($"round {round}: 10 parallel failures exceed the threshold of 5");
            stored.LockoutEnd!.Value.Should().BeAfter(DateTimeOffset.UtcNow);
        }
    }

    [Fact]
    public async Task FailedSignIns_BelowTheThreshold_DoNotLock_AtTheThreshold_Lock()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        for (var i = 1; i <= 4; i++)
        {
            var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            var result = await manager.AccessFailedAsync((await manager.FindByNameAsync(userName))!);
            result.Succeeded.Should().BeTrue("a sequential failed sign-in on a current user is stored without conflict");
            var stored = await FindAsync(repo, userName);
            stored.AccessFailedCount.Should().Be(i);
            stored.LockoutEnd.Should().BeNull();
        }

        var last = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        await last.AccessFailedAsync((await last.FindByNameAsync(userName))!);

        var locked = await FindAsync(repo, userName);
        locked.LockoutEnd.Should().NotBeNull("the fifth failure reaches the threshold");
        locked.AccessFailedCount.Should().Be(0, "the counter restarts after the lockout, as ASP.NET Core Identity does");
    }

    [Fact]
    public async Task SuccessfulSignIn_ResetsTheCounter()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        for (var i = 0; i < 3; i++)
        {
            var failing = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            await failing.AccessFailedAsync((await failing.FindByNameAsync(userName))!);
        }

        (await FindAsync(repo, userName)).AccessFailedCount.Should().Be(3);

        // What SignInManager does after a correct password: ResetLockoutAsync.
        var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var result = await manager.ResetAccessFailedCountAsync((await manager.FindByNameAsync(userName))!);

        result.Succeeded.Should().BeTrue();
        (await FindAsync(repo, userName)).AccessFailedCount.Should().Be(0);
    }

    [Fact]
    public async Task TwoConcurrentProfileUpdates_OneSucceeds_TheOtherGetsConcurrencyFailure_NothingIsLost()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        var managerA = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var managerB = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var userA = (await managerA.FindByNameAsync(userName))!;
        var userB = (await managerB.FindByNameAsync(userName))!;

        userA.PhoneNumber = "+43 1 111";
        userB.FirstName = "Bea";

        var resultA = await managerA.UpdateAsync(userA);
        var resultB = await managerB.UpdateAsync(userB);

        resultA.Succeeded.Should().BeTrue();
        resultB.Succeeded.Should().BeFalse();
        resultB.Errors.Should().ContainSingle(e => e.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);

        var stored = await FindAsync(repo, userName);
        stored.PhoneNumber.Should().Be("+43 1 111", "the field of the first writer is not lost");
        stored.FirstName.Should().NotBe("Bea", "the conflicting write changed nothing");
    }

    [Fact]
    public async Task ProfileUpdate_OnAStaleUser_DoesNotRevertAFailedSignInCount()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        var profileManager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var staleUser = (await profileManager.FindByNameAsync(userName))!;

        var signInManager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        await signInManager.AccessFailedAsync((await signInManager.FindByNameAsync(userName))!);

        staleUser.PhoneNumber = "+43 1 222";
        var result = await profileManager.UpdateAsync(staleUser);

        result.Succeeded.Should().BeFalse("the user changed after it was read");
        var stored = await FindAsync(repo, userName);
        stored.AccessFailedCount.Should().Be(1, "the profile write must not overwrite the counted failure");
        stored.PhoneNumber.Should().NotBe("+43 1 222");
    }

    [Fact]
    public async Task ProfileUpdate_OnAStaleUser_AfterAThresholdLockout_ReturnsConcurrencyFailure_AndKeepsTheLockout()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        var profileManager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var staleUser = (await profileManager.FindByNameAsync(userName))!;

        await RunInParallelAsync(5, async () =>
        {
            var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            await manager.AccessFailedAsync((await manager.FindByNameAsync(userName))!);
        });
        (await FindAsync(repo, userName)).LockoutEnd.Should().NotBeNull("five failures reach the threshold");

        staleUser.PhoneNumber = "+43 1 444";
        var result = await profileManager.UpdateAsync(staleUser);

        result.Succeeded.Should().BeFalse("the lockout changed the user after it was read");
        result.Errors.Should().ContainSingle(e => e.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);
        var stored = await FindAsync(repo, userName);
        stored.LockoutEnd.Should().NotBeNull("a stale profile write must not lift the lockout");
        stored.LockoutEnd!.Value.Should().BeAfter(DateTimeOffset.UtcNow);
        stored.PhoneNumber.Should().NotBe("+43 1 444");
    }

    [Fact]
    public async Task ProfileUpdate_OnAStaleUser_AfterAResetWrite_ReturnsConcurrencyFailure()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);
        var failing = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        await failing.AccessFailedAsync((await failing.FindByNameAsync(userName))!);

        var profileManager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var staleUser = (await profileManager.FindByNameAsync(userName))!;

        var signIn = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        await signIn.AccessFailedAsync((await signIn.FindByNameAsync(userName))!);
        (await FindAsync(repo, userName)).AccessFailedCount.Should().Be(2);

        staleUser.PhoneNumber = "+43 1 555";
        (await profileManager.UpdateAsync(staleUser)).Succeeded.Should().BeFalse();
        (await FindAsync(repo, userName)).AccessFailedCount.Should().Be(2, "the counted failure survives the stale write");
    }

    [Fact]
    public async Task SuccessfulSignInReset_IsNotLost_UnderAConcurrentProfileUpdate()
    {
        for (var round = 0; round < 20; round++)
        {
            var repo = await CreateTenantRepositoryAsync();
            var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);
            var failing = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            await failing.AccessFailedAsync((await failing.FindByNameAsync(userName))!);
            await failing.AccessFailedAsync((await failing.FindByNameAsync(userName))!);

            var profileManager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            var profileUser = (await profileManager.FindByNameAsync(userName))!;

            // The sign-in resets while the profile editor still holds the pre-reset copy.
            var signIn = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            (await signIn.ResetAccessFailedCountAsync((await signIn.FindByNameAsync(userName))!)).Succeeded
                .Should().BeTrue();

            profileUser.PhoneNumber = "+43 1 666";
            var result = await profileManager.UpdateAsync(profileUser);

            result.Succeeded.Should().BeFalse($"round {round}: the stale copy must not win");
            (await FindAsync(repo, userName)).AccessFailedCount.Should().Be(0, "the reset is not undone");
        }
    }

    [Fact]
    public async Task ParallelResetAndProfileUpdate_BothTakeEffect_RepeatedTwentyTimes()
    {
        var repo = await CreateTenantRepositoryAsync();

        for (var round = 0; round < 20; round++)
        {
            var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);
            var failing = CreateUserManager(repo, maxFailedAccessAttempts: 5);
            await failing.AccessFailedAsync((await failing.FindByNameAsync(userName))!);
            await failing.AccessFailedAsync((await failing.FindByNameAsync(userName))!);

            var reset = Task.Run(async () =>
            {
                var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
                await manager.ResetAccessFailedCountAsync((await manager.FindByNameAsync(userName))!);
            }, TestContext.Current.CancellationToken);
            var profile = Task.Run(async () =>
            {
                // A well-behaved caller re-reads on a concurrency failure.
                var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
                IdentityResult result;
                do
                {
                    var user = (await manager.FindByNameAsync(userName))!;
                    user.PhoneNumber = "+43 1 777";
                    result = await manager.UpdateAsync(user);
                } while (!result.Succeeded);
            }, TestContext.Current.CancellationToken);
            await Task.WhenAll(reset, profile);

            var stored = await FindAsync(repo, userName);
            stored.AccessFailedCount.Should().Be(0, $"round {round}: the reset is not undone by the profile write");
            stored.PhoneNumber.Should().Be("+43 1 777");
        }
    }

    [Fact]
    public async Task PlainUserManager_ParallelFailedSignIns_AreAllCounted()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 1000);

        await RunInParallelAsync(10, async () =>
        {
            var manager = CreatePlainUserManager(repo, maxFailedAccessAttempts: 1000);
            await manager.AccessFailedAsync((await manager.FindByNameAsync(userName))!);
        });

        (await FindAsync(repo, userName)).AccessFailedCount.Should().Be(10);
    }

    [Fact]
    public async Task Update_AfterAFailedSignInOnTheSameInstance_Succeeds()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var user = (await manager.FindByNameAsync(userName))!;
        (await manager.AccessFailedAsync(user)).Succeeded.Should().BeTrue();

        user.PhoneNumber = "+43 1 333";
        (await manager.UpdateAsync(user)).Succeeded.Should().BeTrue("the instance followed the stored version");

        var stored = await FindAsync(repo, userName);
        stored.PhoneNumber.Should().Be("+43 1 333");
        stored.AccessFailedCount.Should().Be(1);
    }

    [Fact]
    public async Task EnablingTwoFactor_AfterTokenWrites_OnTheSameInstance_IsStored()
    {
        var repo = await CreateTenantRepositoryAsync();
        var userName = await CreateUserAsync(repo, maxFailedAccessAttempts: 5);

        // The authenticator setup: key and recovery codes are token writes, then the flag is saved with UpdateAsync.
        var manager = CreateUserManager(repo, maxFailedAccessAttempts: 5);
        var user = (await manager.FindByNameAsync(userName))!;
        (await manager.ResetAuthenticatorKeyAsync(user)).Succeeded.Should().BeTrue();
        var codes = await manager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        (await manager.SetTwoFactorEnabledAsync(user, true)).Succeeded.Should().BeTrue();

        codes.Should().HaveCount(10);
        var stored = await FindAsync(repo, userName);
        stored.TwoFactorEnabled.Should().BeTrue();
        stored.UserTokens.Should().NotBeNullOrEmpty();
    }

    private static async Task RunInParallelAsync(int count, Func<Task> action)
    {
        using var gate = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, count).Select(_ => Task.Run(async () =>
        {
            gate.Wait();
            await action();
        })).ToArray();
        gate.Set();
        await Task.WhenAll(tasks);
    }

    private async Task<ITenantRepository> CreateTenantRepositoryAsync()
    {
        var systemContext = _fixture.GetSystemContext();
        var tenantId = $"lockout-{Guid.NewGuid():N}"[..20];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            try
            {
                await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
                await session.CommitTransactionAsync();
            }
            catch
            {
                await session.AbortTransactionAsync();
                throw;
            }
        }

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        return (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
    }

    private async Task<string> CreateUserAsync(ITenantRepository repo, int maxFailedAccessAttempts)
    {
        var userName = $"user-{Guid.NewGuid():N}"[..16];
        var manager = CreateUserManager(repo, maxFailedAccessAttempts);
        var result = await manager.CreateAsync(new RtUser { UserName = userName, Email = $"{userName}@example.com" });
        result.Succeeded.Should().BeTrue();
        return userName;
    }

    private static async Task<RtUser> FindAsync(ITenantRepository repo, string userName)
    {
        var store = new OctoUserStore(new FixedTenantResolver(repo), null!, null);
        return (await store.FindByNameAsync(userName.ToUpperInvariant()))!;
    }

    private OctoUserStore CreateUserStore(ITenantRepository repo)
    {
        var resolver = new FixedTenantResolver(repo);
        return new OctoUserStore(
            resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver),
                new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext())),
            null);
    }

    /// <summary>The manager production registers (AB#7854): failure counting and reset go through the atomic store.</summary>
    private UserManager<RtUser> CreateUserManager(ITenantRepository repo, int maxFailedAccessAttempts)
        => CreateManager(repo, maxFailedAccessAttempts, atomic: true);

    /// <summary>A plain framework manager over the same store (the lockout-store contract, not registered in production).</summary>
    private UserManager<RtUser> CreatePlainUserManager(ITenantRepository repo, int maxFailedAccessAttempts)
        => CreateManager(repo, maxFailedAccessAttempts, atomic: false);

    private UserManager<RtUser> CreateManager(ITenantRepository repo, int maxFailedAccessAttempts, bool atomic)
    {
        var options = new IdentityOptions();
        options.Lockout.MaxFailedAccessAttempts = maxFailedAccessAttempts;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        if (atomic)
        {
            return new OctoUserManager(
                CreateUserStore(repo),
                Microsoft.Extensions.Options.Options.Create(options),
                new PasswordHasher<RtUser>(),
                Array.Empty<IUserValidator<RtUser>>(),
                Array.Empty<IPasswordValidator<RtUser>>(),
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                services: null!,
                NullLogger<UserManager<RtUser>>.Instance);
        }

        return new UserManager<RtUser>(
            CreateUserStore(repo),
            Microsoft.Extensions.Options.Options.Create(options),
            new PasswordHasher<RtUser>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            services: null!,
            NullLogger<UserManager<RtUser>>.Instance);
    }
}
