using FluentAssertions;

using IdentityServices.IntegrationTests.Fixtures;

using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts.DependencyGraph;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#7773 (Feature AB#5696, System.Identity 2.29.0): the identity methods of User, Group, Client and
///     DataPermission are declared in the CK model (declarations only, the handlers follow with AB#5672 and
///     AB#7774, AB#7776-7780). These tests read the compiled model from the CK cache of a real tenant and pin the
///     contract the handlers and the typed GraphQL mutations are built against: the method set, the roles, the
///     sensitive parameters and results, the data access, and that no seeded type replaces the generic create.
/// </summary>
[Collection("Sequential")]
public class IdentityMethodDeclarationsIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string UserManagement = "UserManagement";
    private const string TenantManagement = "TenantManagement";

    private readonly IdentityServicesFixture _fixture;

    public IdentityMethodDeclarationsIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    public static TheoryData<string, string[]> DeclaredMethods => new()
    {
        { "User", ["ChangePassword-1", "ResetPassword-1", "SetRoles-1", "AddRole-1", "RemoveRole-1", "Merge-1", "CreateUser-1"] },
        { "Group", ["AddMember-1", "RemoveMember-1", "SetRoles-1"] },
        { "Client", ["AddSecret-1", "RemoveSecret-1"] },
        { "DataPermission", ["GrantToRole-1", "RevokeFromRole-1"] }
    };

    [Theory]
    [MemberData(nameof(DeclaredMethods))]
    public async Task TheType_DeclaresExactlyTheMethodsOfTheFeature(string type, string[] methodIds)
    {
        var graph = await GetTypeAsync(type);

        graph.DefinedMethods.Select(m => m.MethodId).Should().BeEquivalentTo(methodIds);
        graph.AllMethods.Keys.Should().BeEquivalentTo(methodIds, "the types are final: nothing is inherited");
    }

    [Fact]
    public async Task EveryMethod_IsAuthorized_AndDeclaresWriteAccess_ExceptTheCreate()
    {
        foreach (var type in new[] { "User", "Group", "Client", "DataPermission" })
        {
            var graph = await GetTypeAsync(type);
            foreach (var method in graph.AllMethods.Values)
            {
                var authorization = method.Definition.Authorization;
                authorization.Should().NotBeNull($"{method.QualifiedMethodId} is default-deny without a role");
                (authorization!.AllowSelf == true || authorization.Roles is { Count: > 0 })
                    .Should().BeTrue($"{method.QualifiedMethodId} names a role or allowSelf");
                method.DataAccess.Should().Be(CkMethodDataAccessDto.Write, method.QualifiedMethodId);
                method.Handler.Should().Be("service",
                    $"{method.QualifiedMethodId} has a sensitive or security-relevant payload, never a pipeline");
            }
        }
    }

    [Fact]
    public async Task Roles_FollowTheRestParity()
    {
        var user = await GetTypeAsync("User");
        foreach (var id in new[] { "ResetPassword-1", "SetRoles-1", "AddRole-1", "RemoveRole-1", "Merge-1", "CreateUser-1" })
        {
            user.AllMethods[id].Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement], id);
        }

        var changePassword = user.AllMethods["ChangePassword-1"].Definition.Authorization!;
        changePassword.AllowSelf.Should().BeTrue("a user changes their own password with the current one");
        changePassword.Roles.Should().BeNullOrEmpty("an administrator uses ResetPassword");

        foreach (var type in new[] { "Group", "DataPermission" })
        {
            foreach (var method in (await GetTypeAsync(type)).AllMethods.Values)
            {
                method.Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement], method.QualifiedMethodId);
            }
        }

        foreach (var method in (await GetTypeAsync("Client")).AllMethods.Values)
        {
            method.Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement], method.QualifiedMethodId);
        }
    }

    [Fact]
    public async Task EveryParameterThatCarriesAPasswordOrSecret_IsSensitive_AndNothingElseIs()
    {
        var sensitive = new List<string>();
        foreach (var type in new[] { "User", "Group", "Client", "DataPermission" })
        {
            foreach (var method in (await GetTypeAsync(type)).AllMethods.Values)
            {
                sensitive.AddRange((method.Definition.Parameters ?? [])
                    .Where(p => p.Sensitive).Select(p => $"{method.QualifiedMethodId}({p.Name})"));
            }
        }

        sensitive.Should().BeEquivalentTo(
        [
            "System.Identity/User.ChangePassword-1(currentPassword)",
            "System.Identity/User.ChangePassword-1(newPassword)",
            "System.Identity/User.ResetPassword-1(newPassword)",
            "System.Identity/User.CreateUser-1(password)",
            "System.Identity/Client.RemoveSecret-1(secretValue)"
        ]);
    }

    [Fact]
    public async Task OnlyTheClientAddSecret_HasASensitiveResult_TheGeneratedSecretIsShownOnce()
    {
        var results = new List<string>();
        foreach (var type in new[] { "User", "Group", "Client", "DataPermission" })
        {
            results.AddRange((await GetTypeAsync(type)).AllMethods.Values.Where(m => m.HasSensitiveResult)
                .Select(m => m.QualifiedMethodId));
        }

        results.Should().BeEquivalentTo(["System.Identity/Client.AddSecret-1"]);
        (await GetTypeAsync("Client")).AllMethods["AddSecret-1"].Definition.Result!.ValueType.Should()
            .Be(AttributeValueTypesDto.String);
    }

    [Fact]
    public async Task NoSeededType_ReplacesTheGenericCreate_AndNeitherDoesTheUserYet()
    {
        // Group, Client and DataPermission are seeded by the System.Identity.Bootstrap blueprint: a flag there makes
        // every new tenant's bootstrap fail (AB#7121). The flag on User is a MAJOR change of the model (row M16 of
        // the SemVer rules) and waits for the platform-owner decision recorded on AB#7773.
        foreach (var type in new[] { "User", "Group", "Client", "DataPermission" })
        {
            (await GetTypeAsync(type)).AllMethods.Values.Where(m => m.ReplacesGenericCreate)
                .Should().BeEmpty(type);
        }
    }

    /// <summary>
    ///     AB#5672: the production gate registers the handlers of secret-carrying methods only with
    ///     <c>Methods:Identity:EnablePasswordMethods</c>. The flag of a handler registration must say what the compiled model
    ///     says (a sensitive parameter or result), so a later handler story cannot register a password method past the gate.
    /// </summary>
    [Fact]
    public async Task EveryHandlerRegistration_FlagsASecretCarryingMethod_AsTheModelDeclaresIt()
    {
        IdentityMethodHost.Handlers.Should().NotBeEmpty();
        foreach (var registration in IdentityMethodHost.Handlers)
        {
            var typeAndMethod = registration.MethodId.Split('/')[1];
            var type = typeAndMethod.Split('.')[0];
            var methodId = typeAndMethod.Split('.', 2)[1];
            var method = (await GetTypeAsync(type)).AllMethods[methodId].Definition;
            var carriesSecret = (method.Parameters ?? []).Any(p => p.Sensitive) || method.Result?.Sensitive == true;

            registration.CarriesSecret.Should().Be(carriesSecret, registration.MethodId);
        }
    }

    [Fact]
    public async Task TheMemberKindOfTheGroupMethods_IsTheDeclaredEnum()
    {
        var group = await GetTypeAsync("Group");
        foreach (var id in new[] { "AddMember-1", "RemoveMember-1" })
        {
            var parameter = group.AllMethods[id].Definition.Parameters!.Single(p => p.Name == "memberKind");
            parameter.ValueType.Should().Be(AttributeValueTypesDto.Enum);
            parameter.ValueCkEnumId.Should().NotBeNull();
        }
    }

    private async Task<CkTypeGraph> GetTypeAsync(string type)
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>()
            .SetupAsync(_fixture.GetSystemContext().TenantId);
        return _fixture.GetService<ICkCacheService>().GetRtCkType(
            _fixture.GetSystemContext().TenantId, new RtCkId<CkTypeId>($"System.Identity/{type}"));
    }
}
