using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.Methods;

/// <summary>
///     The caller tenant and the actor name of the cross-tenant methods: the token's own tenant decides on every transport, and
///     the grant audit names the caller by the user name stored for its subject, never by nothing.
/// </summary>
public class CrossTenantMethodSupportTests
{
    private const string TokenTenant = "home";
    private readonly ITenantRepository _repository = Substitute.For<ITenantRepository>();
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly RecordingLogger _log = new();

    public CrossTenantMethodSupportTests()
    {
        _systemContext.TryFindTenantRepositoryAsync(TokenTenant).Returns(_repository);
        _repository.GetSessionAsync().Returns(_ => Substitute.For<IOctoSession>());
    }

    [Fact]
    public void CallerTenant_IsTheTokensTenant_EvenWhenTheBusHostBoundTheCallTenant()
    {
        var bus = new CkMethodPrincipal("s", [], [], null, "call-tenant") { TokenTenantId = TokenTenant };

        CrossTenantMethodSupport.CallerTenantId(bus).Should().Be(TokenTenant);
        CrossTenantMethodSupport.CallerTenantId(new CkMethodPrincipal("s", [], [], null, "call-tenant"))
            .Should().Be("call-tenant", "without a tenant_id claim the validated tenant is the only one known");
    }

    [Fact]
    public async Task ActorName_IsTheStoredUserName_OfTheSubjectInItsTokenTenant()
    {
        var userId = OctoObjectId.GenerateNewId();
        _repository.GetRtEntityByRtIdAsync<RtUser>(Arg.Any<IOctoSession>(), userId)
            .Returns(new RtUser { RtId = userId, UserName = "alice" });

        var name = await CrossTenantMethodSupport.CallerNameAsync(Call(User(userId)), "call-tenant");

        name.Should().Be("alice");
        _log.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task ActorName_WithoutAStoredUser_IsTheSubject_AndAWarningWithoutTheSubjectIsLogged()
    {
        var userId = OctoObjectId.GenerateNewId();
        _repository.GetRtEntityByRtIdAsync<RtUser>(Arg.Any<IOctoSession>(), userId).Returns((RtUser?)null);

        var name = await CrossTenantMethodSupport.CallerNameAsync(Call(User(userId)), "call-tenant");

        name.Should().Be(userId.ToString(), "the actor is never empty");
        _log.Warnings.Should().ContainSingle().Which.Should().NotContain(userId.ToString());
    }

    [Fact]
    public async Task ActorName_OfAServiceCaller_IsItsClientId()
    {
        var service = new CkMethodPrincipal(null, [], [], "svc-client") { TokenTenantId = TokenTenant };

        (await CrossTenantMethodSupport.CallerNameAsync(Call(service), "call-tenant")).Should().Be("svc-client");
    }

    private static CkMethodPrincipal User(OctoObjectId id) =>
        new(id.ToString(), [], []) { TokenTenantId = TokenTenant };

    private IdentityMethodCall Call(CkMethodPrincipal principal) =>
        new(new ServiceCollection()
            .AddSingleton(_systemContext)
            .AddSingleton<ILogger<IdentityMethodCall>>(_log)
            .BuildServiceProvider(), principal);

    private sealed class RecordingLogger : ILogger<IdentityMethodCall>
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
            }
        }
    }
}
