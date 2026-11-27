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
        { "User", ["ChangePassword-1", "SetPassword-1", "ResetPassword-1", "SetRoles-1", "AddRole-1", "RemoveRole-1", "Merge-1", "DisableTwoFactor-1", "CreateUser-1"] },
        {
            "Group",
            [
                "AddMember-1", "RemoveMember-1", "SetRoles-1", "AddChildGroup-1", "RemoveChildGroup-1",
                // System.Identity 3.7.0: create, update and delete
                "CreateGroup-1", "UpdateGroup-1", "DeleteGroup-1"
            ]
        },
        {
            "Client",
            [
                "AddSecret-1", "RemoveSecret-1", "UpdateSecret-1", "SetRoles-1", "AddRole-1", "RemoveRole-1",
                "ApplyOverlayUris-1", "CleanOverlayEntries-1",
                // System.Identity 3.5.0: client mirrors
                "ProvisionMirrors-1", "ProvisionMirrorInTenant-1", "RotateMirrorSecret-1", "RemoveMirror-1",
                "SetMirrorAutoProvision-1",
                // System.Identity 3.8.0: create, update and delete
                "CreateClient-1", "UpdateClient-1", "DeleteClient-1",
                // System.Identity 3.9.0: the roles a client hands to its mirrors
                "SetMirrorRoles-1"
            ]
        },
        {
            "DataPermission",
            [
                "GrantToRole-1", "RevokeFromRole-1",
                // System.Identity 3.8.0: create and delete, and the create of a policy
                "CreateDataPermission-1", "DeleteDataPermission-1", "CreatePolicy-1"
            ]
        },
        // System.Identity 3.4.0
        {
            "ApiResource",
            [
                "AddSecret-1", "RemoveSecret-1", "UpdateSecret-1",
                // System.Identity 3.7.0: create, update and delete
                "CreateApiResource-1", "UpdateApiResource-1", "DeleteApiResource-1"
            ]
        },
        { "DataPolicy", ["SetEnforcementMode-1", "DeleteDataPolicy-1"] },
        // System.Identity 3.5.0: admin provisioning and the mapping create
        {
            "ExternalTenantUserMapping",
            [
                "ProvisionAdmin-1", "ProvisionAdminWithGroups-1", "ProvisionCurrentUser-1", "RemoveAdminProvisioning-1",
                "CreateMapping-1",
                // System.Identity 3.8.0: update and delete
                "UpdateMapping-1", "DeleteMapping-1"
            ]
        },
        // System.Identity 3.7.0: create, update and delete of roles and API scopes
        { "Role", ["CreateRole-1", "UpdateRole-1", "DeleteRole-1"] },
        { "ApiScope", ["CreateApiScope-1", "UpdateApiScope-1", "DeleteApiScope-1"] },
        // System.Identity 3.8.0: create, update and delete of e-mail domain group rules and identity providers (the abstract
        // base declares them; the concrete provider types inherit them)
        {
            "EmailDomainGroupRule",
            ["CreateEmailDomainGroupRule-1", "UpdateEmailDomainGroupRule-1", "DeleteEmailDomainGroupRule-1"]
        },
        { "IdentityProvider", ["CreateIdentityProvider-1", "UpdateIdentityProvider-1", "DeleteIdentityProvider-1"] }
    };

    private static readonly string[] MethodTypes =
        ["User", "Group", "Client", "DataPermission", "ApiResource", "DataPolicy", "ExternalTenantUserMapping", "Role",
            "ApiScope", "EmailDomainGroupRule", "IdentityProvider"];

    [Theory]
    [MemberData(nameof(DeclaredMethods))]
    public async Task TheType_DeclaresExactlyTheMethodsOfTheFeature(string type, string[] methodIds)
    {
        var graph = await GetTypeAsync(type);

        graph.DefinedMethods.Select(m => m.MethodId).Should().BeEquivalentTo(methodIds);
        graph.AllMethods.Keys.Should().BeEquivalentTo(methodIds, "nothing is inherited from a base type");
    }

    [Theory]
    [InlineData("GoogleIdentityProvider")]
    [InlineData("MicrosoftIdentityProvider")]
    [InlineData("FacebookIdentityProvider")]
    [InlineData("AzureEntraIdIdentityProvider")]
    [InlineData("MicrosoftAdIdentityProvider")]
    [InlineData("OpenLdapIdentityProvider")]
    [InlineData("OctoTenantIdentityProvider")]
    public async Task EveryConcreteProviderType_InheritsTheProviderMethods_AndStoresNoReadableSecret(string type)
    {
        // System.Identity 3.8.0: the GraphQL gateway exposes methods only on concrete types (an abstract type has no
        // mutation field), so each provider type must carry the inherited CRUD methods.
        var graph = await GetTypeAsync(type);
        graph.AllMethods.Keys.Should().BeEquivalentTo(
            ["CreateIdentityProvider-1", "UpdateIdentityProvider-1", "DeleteIdentityProvider-1"], type);

        // No GraphQL read returns a provider secret: the client secret is a Secret value (never projected, only "is set");
        // the LDAP providers store no password at all.
        foreach (var attribute in graph.AllAttributesByName)
        {
            if (attribute.Key.Contains("Secret", StringComparison.OrdinalIgnoreCase))
            {
                attribute.Value.ValueType.Should().Be(AttributeValueTypesDto.Secret, $"{type}.{attribute.Key}");
            }

            attribute.Key.Should().NotContainEquivalentOf("password", $"{type} stores no password");
        }
    }

    [Fact]
    public async Task EveryMethod_IsAuthorized_AndDeclaresWriteAccess_ExceptTheCreate()
    {
        foreach (var type in MethodTypes)
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
        foreach (var id in new[] { "ResetPassword-1", "SetRoles-1", "AddRole-1", "RemoveRole-1", "Merge-1", "DisableTwoFactor-1", "CreateUser-1" })
        {
            user.AllMethods[id].Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement], id);
        }

        var changePassword = user.AllMethods["ChangePassword-1"].Definition.Authorization!;
        changePassword.AllowSelf.Should().BeTrue("a user changes their own password with the current one");
        changePassword.Roles.Should().BeNullOrEmpty("an administrator uses ResetPassword");

        // AB#8414 (System.Identity 3.2.0): the account page's first password, self only like ChangePassword.
        var setPassword = user.AllMethods["SetPassword-1"].Definition.Authorization!;
        setPassword.AllowSelf.Should().BeTrue("a user with external logins only sets their own first password");
        setPassword.Roles.Should().BeNullOrEmpty("an administrator uses ResetPassword");

        foreach (var type in new[] { "Group", "DataPermission", "DataPolicy" })
        {
            foreach (var method in (await GetTypeAsync(type)).AllMethods.Values)
            {
                method.Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement], method.QualifiedMethodId);
            }
        }

        // AB#8095 (System.Identity 3.1.0): SecretManagement joins the REST-parity roles of the client secret methods; the
        // handler still requires SecretManagement under Enforce. TenantManagement/UserManagement leave with the next major.
        // System.Identity 3.4.0: UpdateSecret and the API resource secret methods carry the same roles.
        var client = await GetTypeAsync("Client");
        var apiResource = await GetTypeAsync("ApiResource");
        foreach (var method in new[] { "AddSecret-1", "RemoveSecret-1", "UpdateSecret-1" }
                     .SelectMany(id => new[] { client.AllMethods[id], apiResource.AllMethods[id] }))
        {
            method.Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement, "SecretManagement"], method.QualifiedMethodId);
        }

        // System.Identity 3.5.0: the mirror methods carry the REST policies of ClientMirrorController (the rotation the secret
        // policy), the provisioning methods the policy of AdminProvisioningController, the mapping create the policy of
        // ExternalTenantUserMappingsController.
        foreach (var id in new[] { "ProvisionMirrors-1", "ProvisionMirrorInTenant-1", "RemoveMirror-1", "SetMirrorAutoProvision-1" })
        {
            client.AllMethods[id].Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement], id);
        }

        client.AllMethods["RotateMirrorSecret-1"].Definition.Authorization!.Roles.Should()
            .BeEquivalentTo([TenantManagement, UserManagement, "SecretManagement"]);

        // System.Identity 3.9.0: the mirror role list reaches every child tenant, so only TenantManagement may set it.
        client.AllMethods["SetMirrorRoles-1"].Definition.Authorization!.Roles.Should().BeEquivalentTo([TenantManagement]);
        var mapping = await GetTypeAsync("ExternalTenantUserMapping");
        foreach (var id in new[] { "ProvisionAdmin-1", "ProvisionAdminWithGroups-1", "ProvisionCurrentUser-1", "RemoveAdminProvisioning-1" })
        {
            mapping.AllMethods[id].Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement], id);
        }

        mapping.AllMethods["CreateMapping-1"].Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement]);

        // System.Identity 3.8.0: the mapping update and delete carry the policy of ExternalTenantUserMappingsController
        // (UserManagement); the client, provider and rule CRUD the tenant administration policy (TenantManagement or
        // UserManagement; a client secret also needs SecretManagement in the handler). The data permission and policy CRUD is
        // covered by the UserManagement loop above.
        foreach (var id in new[] { "UpdateMapping-1", "DeleteMapping-1" })
        {
            mapping.AllMethods[id].Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement], id);
        }

        foreach (var method in new[] { "CreateClient-1", "UpdateClient-1", "DeleteClient-1" }
                     .Select(id => client.AllMethods[id])
                     .Concat((await GetTypeAsync("IdentityProvider")).AllMethods.Values)
                     .Concat((await GetTypeAsync("EmailDomainGroupRule")).AllMethods.Values))
        {
            method.Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement], method.QualifiedMethodId);
        }

        // System.Identity 3.7.0: the CRUD methods carry the REST policies of RolesController (UserManagement; the group CRUD
        // is covered by the Group loop above), ApiScopesController and ApiResourcesController (TenantManagement or
        // UserManagement).
        foreach (var method in (await GetTypeAsync("Role")).AllMethods.Values)
        {
            method.Definition.Authorization!.Roles.Should().BeEquivalentTo([UserManagement], method.QualifiedMethodId);
        }

        foreach (var method in (await GetTypeAsync("ApiScope")).AllMethods.Values.Concat(new[]
                     { "CreateApiResource-1", "UpdateApiResource-1", "DeleteApiResource-1" }
                     .Select(id => apiResource.AllMethods[id])))
        {
            method.Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement], method.QualifiedMethodId);
        }

        // System.Identity 3.3.0: the client role and overlay methods carry the REST policy of ClientsController
        // (IdentityTenantAdministrationWritePolicy: TenantManagement or UserManagement).
        foreach (var id in new[] { "SetRoles-1", "AddRole-1", "RemoveRole-1", "ApplyOverlayUris-1", "CleanOverlayEntries-1" })
        {
            client.AllMethods[id].Definition.Authorization!.Roles.Should()
                .BeEquivalentTo([TenantManagement, UserManagement], id);
        }
    }

    [Fact]
    public async Task EveryParameterThatCarriesAPasswordOrSecret_IsSensitive_AndNothingElseIs()
    {
        var sensitive = new List<string>();
        foreach (var type in MethodTypes)
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
            "System.Identity/User.SetPassword-1(newPassword)",
            "System.Identity/User.ResetPassword-1(newPassword)",
            "System.Identity/User.CreateUser-1(password)",
            "System.Identity/Client.RemoveSecret-1(secretValue)",
            "System.Identity/Client.UpdateSecret-1(secretValue)",
            "System.Identity/ApiResource.RemoveSecret-1(secretValue)",
            "System.Identity/ApiResource.UpdateSecret-1(secretValue)",
            // System.Identity 3.8.0: the write-only client secret of the provider and client create/update
            "System.Identity/IdentityProvider.CreateIdentityProvider-1(clientSecret)",
            "System.Identity/IdentityProvider.UpdateIdentityProvider-1(clientSecret)",
            "System.Identity/Client.CreateClient-1(clientSecret)",
            "System.Identity/Client.UpdateClient-1(clientSecret)"
        ]);
    }

    [Fact]
    public async Task OnlyTheSecretIssuingMethods_HaveASensitiveResult_TheGeneratedSecretIsShownOnce()
    {
        var results = new List<string>();
        foreach (var type in MethodTypes)
        {
            results.AddRange((await GetTypeAsync(type)).AllMethods.Values.Where(m => m.HasSensitiveResult)
                .Select(m => m.QualifiedMethodId));
        }

        results.Should().BeEquivalentTo(["System.Identity/Client.AddSecret-1", "System.Identity/ApiResource.AddSecret-1",
            "System.Identity/Client.RotateMirrorSecret-1"]);
        foreach (var type in new[] { "Client", "ApiResource" })
        {
            (await GetTypeAsync(type)).AllMethods["AddSecret-1"].Definition.Result!.ValueType.Should()
                .Be(AttributeValueTypesDto.String, type);
        }
    }

    [Fact]
    public async Task OnlyTheUserCreateUser_ReplacesTheGenericCreate_NoSeededTypeDoes()
    {
        // Group, Client and DataPermission are seeded by the System.Identity.Bootstrap blueprint: a flag there makes
        // every new tenant's bootstrap fail (AB#7121). The flag on User (Major, row M16) is set since System.Identity 3.0.0
        // (AB#8053): a user is created only by User.CreateUser-1 or the REST API, never through the generic create.
        // ExternalTenantUserMapping: the flag on CreateMapping-1 is a Major on this existing type (row M16) and waits for the
        // next System.Identity major.
        foreach (var type in new[]
                 {
                     "Group", "Client", "DataPermission", "ApiResource", "DataPolicy", "ExternalTenantUserMapping", "Role",
                     "ApiScope", "EmailDomainGroupRule", "IdentityProvider"
                 })
        {
            (await GetTypeAsync(type)).AllMethods.Values.Where(m => m.ReplacesGenericCreate)
                .Should().BeEmpty(type);
        }

        (await GetTypeAsync("User")).AllMethods.Values.Where(m => m.ReplacesGenericCreate)
            .Select(m => m.QualifiedMethodId).Should().BeEquivalentTo(["System.Identity/User.CreateUser-1"]);
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

    [Fact]
    public async Task TheEnforcementModeOfSetEnforcementMode_IsTheDeclaredEnumOfThePolicyAttribute()
    {
        var parameter = (await GetTypeAsync("DataPolicy")).AllMethods["SetEnforcementMode-1"].Definition.Parameters!
            .Single(p => p.Name == "enforcementMode");
        parameter.ValueType.Should().Be(AttributeValueTypesDto.Enum);
        parameter.ValueCkEnumId.Should().NotBeNull();
        parameter.ValueCkEnumId!.ToString().Should().Contain("DataPolicyEnforcementMode");
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
