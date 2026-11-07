using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#8079: the wire form of <c>User.CreateUser-1</c>. The handler returns <c>UserCreateUserResult { Value = rtId }</c>; the
///     response envelope must carry the bare JSON string <c>"&lt;rtId&gt;"</c> (<c>method-wire-contract.md</c>), not the wrapper
///     <c>{"value":"&lt;rtId&gt;"}</c> that the asset-repo gateway used to hand to the client as the String result. The call goes
///     through the real host core of octo-common-services (registration, parameter JSON, authorization, handler adapter, result
///     serialization), the in-process transport, which produces the envelope of the bus path. The bus registration of the handler is
///     off (<c>EnablePasswordMethods</c> false), so the host registers it local only (AB#8413), in-process.
/// </summary>
public sealed class UserCreateUserWireFormTests : IntegrationTestBase, IDisposable
{
    private readonly WebApplicationFactory<Program> _host;

    public UserCreateUserWireFormTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            // no broker in the test host
            foreach (var descriptor in services
                         .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                             or "CkMethodHandlerHeartbeatService").ToList())
            {
                services.Remove(descriptor);
            }

            services.RemoveAll<IUserEmailInteractionService>();
            services.AddSingleton(Substitute.For<IUserEmailInteractionService>());
            // Since AB#8413 the host itself registers the handler local only while EnablePasswordMethods is off (the REST
            // facade POST users calls it in-process); a second registration here would be refused at start.
        }));
    }

    public void Dispose() => _host.Dispose();

    [Fact]
    public async Task CreateUser_ResultJson_IsTheBareRtIdString()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"m8079_{Guid.NewGuid():N}";
        var transport = _host.Services.GetRequiredService<ICkInProcessMethodTransport>();

        CkMethodResponse response;
        using (CkMethodPrincipalScope.Begin(
                   new CkMethodPrincipal("507f1f77bcf86cd799439012", ["UserManagement"], ["octo_api"])))
        {
            response = await transport.InvokeAsync(new CkMethodRequest(NormalizedSystemTenantId)
            {
                InvocationId = Guid.NewGuid(),
                MethodId = SystemIdentityCkIds.UserCreateUserMethodId,
                CkTypeId = "System.Identity/User",
                DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
                ParametersJson = JsonSerializer.Serialize(new { userName, email = $"{userName}@example.invalid" })
            }, ct);
        }

        response.Success.Should().BeTrue(response.Error?.Code);
        RtUser? stored;
        using (var scope = _host.Services.CreateScope())
        {
            stored = await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
        }

        stored.Should().NotBeNull();
        response.ResultJson.Should().Be(JsonSerializer.Serialize(stored!.RtId.ToString()),
            "resultJson is the bare JSON string of the rtId, not a value wrapper object");
        using var document = JsonDocument.Parse(response.ResultJson!);
        document.RootElement.ValueKind.Should().Be(JsonValueKind.String);
        document.RootElement.GetString().Should().Be(stored.RtId.ToString());
    }
}
