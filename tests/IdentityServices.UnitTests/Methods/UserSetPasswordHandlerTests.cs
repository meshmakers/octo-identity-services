using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.Methods;

/// <summary>
///     AB#8414 (CodeRabbit finding on PR #272): the existing-password pre-check and <c>AddPasswordAsync</c> are not atomic.
///     When a concurrent call (double submit) sets a password in between, <c>AddPasswordAsync</c> fails with
///     <c>UserAlreadyHasPassword</c>; the method answers the declared <c>PASSWORD_ALREADY_SET</c>, never a policy violation.
/// </summary>
public class UserSetPasswordHandlerTests
{
    private const string Target = "507f1f77bcf86cd799439011";

    [Fact]
    public async Task APasswordSetConcurrently_IsPasswordAlreadySet_NotAPolicyViolation_AndRevokesNothing()
    {
        var describer = new IdentityErrorDescriber();
        var (services, credentialChange, audit) = Services(IdentityResult.Failed(describer.UserAlreadyHasPassword()));
        var handler = new UserSetPasswordHandler(services, NullLogger<UserSetPasswordHandler>.Instance);

        var outcome = await handler.HandleAsync(Context(), TestContext.Current.CancellationToken);

        outcome.Failure!.Code.Should().Be(UserSetPasswordHandler.PasswordAlreadySet);
        await credentialChange.DidNotReceiveWithAnyArgs().OnPasswordChangedAsync(default!, default, default, TestContext.Current.CancellationToken);
        audit.Outcomes.Should().Equal(UserSetPasswordHandler.PasswordAlreadySet);
    }

    [Fact]
    public async Task APolicyFailure_StaysAPolicyViolation_WithTheRuleCodes()
    {
        var describer = new IdentityErrorDescriber();
        var (services, _, _) = Services(IdentityResult.Failed(describer.PasswordTooShort(6)));
        var handler = new UserSetPasswordHandler(services, NullLogger<UserSetPasswordHandler>.Instance);

        var outcome = await handler.HandleAsync(Context(), TestContext.Current.CancellationToken);

        outcome.Failure!.Code.Should().Be(UserSetPasswordHandler.PasswordPolicyViolation);
        outcome.Failure.Details.Should().ContainSingle().Which.Code.Should().Be("PasswordTooShort");
    }

    private static CkMethodContext<UserSetPasswordParameters> Context() => new(new CkMethodRequest("t1")
        {
            InvocationId = Guid.NewGuid(),
            MethodId = SystemIdentityCkIds.UserSetPasswordMethodId,
            CkTypeId = "System.Identity/User",
            TargetRtId = Target,
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        }, new UserSetPasswordParameters { NewPassword = "N3w!Passw0rd-8414" })
        { CallerPrincipal = new CkMethodPrincipal(Target, [], ["octo_api"]) };

    private static (IServiceProvider Services, IUserCredentialChangeService CredentialChange, RecordingAudit Audit)
        Services(IdentityResult addPasswordResult)
    {
        var userManager = Substitute.For<UserManager<RtUser>>(
            Substitute.For<IUserStore<RtUser>>(), null, null, null, null, null, null, null, null);
        userManager.FindByIdAsync(Target).Returns(new RtUser { UserName = "alice" });
        userManager.HasPasswordAsync(Arg.Any<RtUser>()).Returns(false);
        userManager.AddPasswordAsync(Arg.Any<RtUser>(), Arg.Any<string>()).Returns(addPasswordResult);
        var credentialChange = Substitute.For<IUserCredentialChangeService>();
        var audit = new RecordingAudit();
        var services = new ServiceCollection()
            .AddSingleton(userManager)
            .AddSingleton<IMethodTenantAccessor>(new BoundTenant())
            .AddSingleton(credentialChange)
            .AddSingleton<IIdentityMethodAuditWriter>(audit)
            .BuildServiceProvider();
        return (services, credentialChange, audit);
    }

    private sealed class BoundTenant : IMethodTenantAccessor
    {
        public Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories.ITenantRepository? TenantRepository => null;

        public Task<bool> BindAsync(string tenantId) => Task.FromResult(true);
    }

    private sealed class RecordingAudit : IIdentityMethodAuditWriter
    {
        public List<string> Outcomes { get; } = [];

        public Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId,
            string? callerSubject, string outcome, IReadOnlyDictionary<string, string>? extraDetails = null)
        {
            Outcomes.Add(outcome);
            return Task.CompletedTask;
        }
    }
}
