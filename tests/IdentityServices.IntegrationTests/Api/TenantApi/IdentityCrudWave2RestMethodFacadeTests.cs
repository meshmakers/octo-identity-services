using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     the REST create, update and delete endpoints of identity providers, e-mail domain group rules, data permissions
///     and policies and clients, and the update and delete of external tenant user mappings, are facades of the
///     System.Identity 3.8.0 methods. Real MongoDB, real identity host (the secret-carrying methods registered on the bus,
///     <c>Methods:Identity:EnablePasswordMethods=true</c>, so the dispatcher path is the GraphQL gateway's). The tests prove:
///     REST and the method leave the same stored state (parity per type); a secret is written but never returned, neither by
///     REST nor in a method result or audit event; the REST policy and the declared roles; another tenant's token, a caller
///     without the role and a caller who may not write the type are refused and change nothing; the Bootstrap seeds still
///     import.
/// </summary>
public class IdentityCrudWave2RestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";
    private const string TenantManagement = "TenantManagement";
    private const string SecretManagement = "SecretManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public IdentityCrudWave2RestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    private static readonly string GoogleCkTypeId = IdentityProviderMethodSupport.CkTypeIdOf<RtGoogleIdentityProvider>();
    private static readonly string OpenLdapCkTypeId = IdentityProviderMethodSupport.CkTypeIdOf<RtOpenLdapIdentityProvider>();

    private static readonly string[] EndpointNames =
    [
        "createProvider", "updateProvider", "deleteProvider", "createRule", "updateRule", "deleteRule", "updateMapping",
        "deleteMapping", "createPermission", "deletePermission", "createPolicy", "deletePolicy", "createClient",
        "updateClient", "deleteClient"
    ];

    public static TheoryData<string> Endpoints => new(EndpointNames);

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task EveryEndpoint_RunsItsMethodInProcess_OutsideTheRequest_WithExactlyOneIdentityMethodEvent(
        string endpoint)
    {
        var host = Host();
        var caller = FacadeCaller.User(UserManagement, TenantManagement);
        using var client = caller.Client(host);

        var call = await CallAsync(client, endpoint);

        call.Response.StatusCode.Should().Be(call.Expected,
            $"{endpoint}: {await call.Response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        var events = _audit.All.Where(e => e.GetValueOrDefault("methodId") == call.MethodId).ToList();
        events.Should().ContainSingle(endpoint);
        events[0]["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        events[0]["callerSubject"].Should().Be(caller.Subject);
        events[0].GetValueOrDefault("targetRtId").Should().NotBeNullOrEmpty("the created or changed entity is the target");
        _probe.Calls.Should().BeGreaterThan(0, "the method ran through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task ACallerWithoutTheRestPolicyRole_Is403_AndNoMethodRuns(string endpoint)
    {
        var host = Host();
        using var client = FacadeCaller.User("CommunicationManagement").Client(host);

        var call = await CallAsync(client, endpoint);

        call.Response.StatusCode.Should().Be(HttpStatusCode.Forbidden, endpoint);
        _audit.All.Where(e => e.GetValueOrDefault("methodId") == call.MethodId).Should().BeEmpty();
    }

    [Fact]
    public async Task MappingAndDataPermissionEndpoints_StillRequireUserManagement_TenantManagementIsNotEnough()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var mapping = await NewMappingAsync();

        (await client.PostAsJsonAsync(TenantApiUrl("dataPermissions"), new DataPermissionDto { PermissionId = NewName("p") },
            ct)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await client.DeleteAsync(TenantApiUrl($"externalTenantUserMappings/{mapping.RtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.Forbidden);
        // the provider, rule and client endpoints accept TenantManagement (IdentityTenantAdministrationWritePolicy)
        (await client.PostAsJsonAsync(TenantApiUrl("emailDomainGroupRules"), RuleDto(NewName("d")), ct)).StatusCode
            .Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task IdentityProvider_RestAndTheMethod_StoreTheSameProvider_AndTheSecretIsNeverReturned()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var admin = Admin(TenantManagement);
        var ct = TestContext.Current.CancellationToken;
        var restSecret = $"rest-secret-{Guid.NewGuid():N}";
        var methodSecret = $"method-secret-{Guid.NewGuid():N}";

        IdentityProviderDto dto = GoogleDto(NewName("g"), restSecret);
        var rest = await client.PostAsJsonAsync(TenantApiUrl("identityProviders"), dto, ct);
        var restBody = await rest.Content.ReadAsStringAsync(ct);
        rest.StatusCode.Should().Be(HttpStatusCode.OK, restBody);
        restBody.Should().NotContain(restSecret).And.Contain("\"clientSecretIsSet\":true");
        var restRtId = JsonDocument.Parse(restBody).RootElement.GetProperty("rtId").GetString()!;

        var methodName = NewName("g");
        var created = await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
            GoogleCkTypeId, null, GoogleParameters(methodName, methodSecret));
        created.Success.Should().BeTrue(created.Error?.Code);
        created.ResultJson.Should().NotContain(methodSecret, "the result is the rtId only");
        var methodRtId = JsonSerializer.Deserialize<string>(created.ResultJson!)!;

        var restStored = await LoadAsync<RtGoogleIdentityProvider>(OctoObjectId.Parse(restRtId));
        var methodStored = await LoadAsync<RtGoogleIdentityProvider>(OctoObjectId.Parse(methodRtId));
        foreach (var stored in new[] { restStored!, methodStored! })
        {
            stored.ClientId.Should().Be("google-client");
            stored.IsEnabled.Should().BeTrue();
            stored.AllowSelfRegistration.Should().BeFalse();
            stored.Description.Should().Be("A provider");
            stored.ClientSecret!.IsProtected.Should().BeTrue("the secret is stored as an encrypted envelope");
        }

        methodStored!.ClientSecret!.Envelope.Should().NotContain(methodSecret);
        AllEventText().Should().NotContain(restSecret).And.NotContain(methodSecret, "no secret in an audit event");

        // Replace without a secret keeps the stored one; called on another concrete type the target is not found.
        var envelopeBefore = methodStored.ClientSecret.Envelope;
        (await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderUpdateIdentityProviderMethodId, GoogleCkTypeId,
            methodRtId, GoogleUpdateParameters(methodName))).Success.Should().BeTrue();
        (await LoadAsync<RtGoogleIdentityProvider>(OctoObjectId.Parse(methodRtId)))!.ClientSecret!.Envelope.Should()
            .Be(envelopeBefore);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId,
            OpenLdapCkTypeId, methodRtId, new IdentityProviderDeleteIdentityProviderParameters())).Error!.Code.Should()
            .Be(CkMethodErrorCodes.MethodTargetNotFound);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
                "System.Identity/IdentityProvider", null, GoogleParameters(NewName("g"), methodSecret))).Error!.Code
            .Should().Be(CkMethodErrorCodes.MethodValidationFailed, "the abstract base is no provider type");

        // Delete: REST and the method; an unknown id is 404 / METHOD_TARGET_NOT_FOUND.
        (await client.DeleteAsync(TenantApiUrl($"identityProviders/{restRtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId,
            GoogleCkTypeId, methodRtId, new IdentityProviderDeleteIdentityProviderParameters())).Success.Should().BeTrue();
        (await LoadAsync<RtGoogleIdentityProvider>(OctoObjectId.Parse(restRtId))).Should().BeNull();
        (await LoadAsync<RtGoogleIdentityProvider>(OctoObjectId.Parse(methodRtId))).Should().BeNull();
        (await client.DeleteAsync(TenantApiUrl($"identityProviders/{restRtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task LdapProvider_RestAndTheMethod_ApplyTheSameDefaults_AndRefuseAMissingField()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var admin = Admin(TenantManagement);
        var ct = TestContext.Current.CancellationToken;

        IdentityProviderDto dto = new OpenLdapProviderDto
        {
            Name = NewName("l"), IsEnabled = true, Host = "ldap.example.test", UserBaseDn = "ou=people,dc=example"
        };
        var rest = await client.PostAsJsonAsync(TenantApiUrl("identityProviders"), dto, ct);
        rest.StatusCode.Should().Be(HttpStatusCode.OK, await rest.Content.ReadAsStringAsync(ct));
        var restRtId = (await rest.Content.ReadFromJsonAsync<IdentityProviderDto>(ct))!.RtId!.Value;
        var created = await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
            OpenLdapCkTypeId, null, new IdentityProviderCreateIdentityProviderParameters
            {
                Name = NewName("l"), Enabled = true, Host = "ldap.example.test", UserBaseDn = "ou=people,dc=example"
            });
        created.Success.Should().BeTrue(created.Error?.Code);

        var restStored = await LoadAsync<RtOpenLdapIdentityProvider>(restRtId);
        var methodStored =
            await LoadAsync<RtOpenLdapIdentityProvider>(OctoObjectId.Parse(JsonSerializer.Deserialize<string>(created.ResultJson!)!));
        methodStored!.Port.Should().Be(restStored!.Port).And.Be(636);
        methodStored.UseTls.Should().Be(restStored.UseTls).And.BeTrue();
        methodStored.UserNameAttribute.Should().Be(restStored.UserNameAttribute).And.Be("uid");

        var missing = await DispatchAsync(host, admin, SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
            OpenLdapCkTypeId, null, new IdentityProviderCreateIdentityProviderParameters { Name = NewName("l"), Enabled = true });
        missing.Error!.Code.Should().Be(CkMethodErrorCodes.MethodValidationFailed);
        missing.Error.Parameters.Should().Contain(CkMethodErrorParameters.Field, "host");
    }

    [Fact]
    public async Task EmailDomainGroupRule_RestAndTheMethod_StoreTheSameRule()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var admin = Admin(TenantManagement);
        var ct = TestContext.Current.CancellationToken;

        var rest = await client.PostAsJsonAsync(TenantApiUrl("emailDomainGroupRules"), RuleDto(NewName("r")), ct);
        rest.StatusCode.Should().Be(HttpStatusCode.Created);
        var restRule = (await rest.Content.ReadFromJsonAsync<EmailDomainGroupRuleDto>(ct))!;
        var methodPattern = NewName("m");
        var created = await DispatchAsync(host, admin,
            SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId,
            IdentityMethodFacade.EmailDomainGroupRuleCkTypeId, null,
            new EmailDomainGroupRuleCreateEmailDomainGroupRuleParameters
            {
                EmailDomainPattern = methodPattern, TargetGroupRtId = restRule.TargetGroupRtId!, Description = "A rule"
            });
        created.Success.Should().BeTrue(created.Error?.Code);
        var methodRtId = OctoObjectId.Parse(JsonSerializer.Deserialize<string>(created.ResultJson!)!);

        var methodRule = await WithStoreAsync<IEmailDomainGroupRuleStore, RtEmailDomainGroupRule?>(s => s.GetByIdAsync(methodRtId));
        methodRule!.TargetGroupRtId.Should().Be(restRule.TargetGroupRtId);
        methodRule.Description.Should().Be(restRule.Description);

        // update via REST (description omitted clears it) and via the method; unknown id = 404 / not found
        var put = await client.PutAsJsonAsync(TenantApiUrl($"emailDomainGroupRules/{restRule.RtId}"),
            new EmailDomainGroupRuleDto { EmailDomainPattern = restRule.EmailDomainPattern, TargetGroupRtId = "g2" }, ct);
        put.StatusCode.Should().Be(HttpStatusCode.OK);
        (await put.Content.ReadFromJsonAsync<EmailDomainGroupRuleDto>(ct))!.Description.Should().BeNull();
        (await DispatchAsync(host, admin, SystemIdentityCkIds.EmailDomainGroupRuleUpdateEmailDomainGroupRuleMethodId,
            IdentityMethodFacade.EmailDomainGroupRuleCkTypeId, methodRtId.ToString(),
            new EmailDomainGroupRuleUpdateEmailDomainGroupRuleParameters
            {
                EmailDomainPattern = methodPattern, TargetGroupRtId = "g2"
            })).Success.Should().BeTrue();
        (await WithStoreAsync<IEmailDomainGroupRuleStore, RtEmailDomainGroupRule?>(s => s.GetByIdAsync(methodRtId)))!
            .TargetGroupRtId.Should().Be("g2");
        (await client.PutAsJsonAsync(TenantApiUrl($"emailDomainGroupRules/{OctoObjectId.GenerateNewId()}"),
            RuleDto(NewName("x")), ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);

        (await client.DeleteAsync(TenantApiUrl($"emailDomainGroupRules/{restRule.RtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.EmailDomainGroupRuleDeleteEmailDomainGroupRuleMethodId,
            IdentityMethodFacade.EmailDomainGroupRuleCkTypeId, methodRtId.ToString(),
            new EmailDomainGroupRuleDeleteEmailDomainGroupRuleParameters())).Success.Should().BeTrue();
        (await client.DeleteAsync(TenantApiUrl($"emailDomainGroupRules/{restRule.RtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Mapping_RestAndTheMethod_ReplaceTheRolesAlike_AndDelete()
    {
        var host = Host();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var admin = Admin(UserManagement);
        var ct = TestContext.Current.CancellationToken;
        var restMapping = await NewMappingAsync();
        var methodMapping = await NewMappingAsync();
        var roleIds = new List<string> { OctoObjectId.GenerateNewId().ToString() };

        (await client.PutAsJsonAsync(TenantApiUrl($"externalTenantUserMappings/{restMapping.RtId}"),
            new UpdateExternalTenantUserMappingDto { RoleIds = roleIds }, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ExternalTenantUserMappingUpdateMappingMethodId,
            IdentityMethodFacade.ExternalTenantUserMappingCkTypeId, methodMapping.RtId.ToString(),
            new ExternalTenantUserMappingUpdateMappingParameters { RoleIds = roleIds })).Success.Should().BeTrue();

        var rest = await WithStoreAsync<IExternalTenantUserMappingStore, RtExternalTenantUserMapping?>(s =>
            s.GetByIdAsync(restMapping.RtId));
        var method = await WithStoreAsync<IExternalTenantUserMappingStore, RtExternalTenantUserMapping?>(s =>
            s.GetByIdAsync(methodMapping.RtId));
        rest!.MappedRoleIds.Should().Equal(roleIds);
        method!.MappedRoleIds.Should().Equal(roleIds);
        method.SourceUserId.Should().Be(methodMapping.SourceUserId, "the source user never changes");

        (await client.DeleteAsync(TenantApiUrl($"externalTenantUserMappings/{restMapping.RtId}"), ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ExternalTenantUserMappingDeleteMappingMethodId,
            IdentityMethodFacade.ExternalTenantUserMappingCkTypeId, methodMapping.RtId.ToString(),
            new ExternalTenantUserMappingDeleteMappingParameters())).Success.Should().BeTrue();
        (await WithStoreAsync<IExternalTenantUserMappingStore, RtExternalTenantUserMapping?>(s =>
            s.GetByIdAsync(methodMapping.RtId))).Should().BeNull();
        (await client.DeleteAsync(TenantApiUrl($"externalTenantUserMappings/{restMapping.RtId}"), ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task DataPermission_RestAndTheMethod_CreateThePermissionAndPolicyAlike_AndDeleteThem()
    {
        var host = Host();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var admin = Admin(UserManagement);
        var ct = TestContext.Current.CancellationToken;
        var restId = NewName("dp.rest");
        var methodId = NewName("dp.method");

        (await client.PostAsJsonAsync(TenantApiUrl("dataPermissions"),
            new DataPermissionDto { PermissionId = restId, Description = "d" }, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        var created = await DispatchAsync(host, admin, SystemIdentityCkIds.DataPermissionCreateDataPermissionMethodId,
            IdentityMethodFacade.DataPermissionCkTypeId, null,
            new DataPermissionCreateDataPermissionParameters { PermissionId = methodId, Description = "d" });
        created.Success.Should().BeTrue(created.Error?.Code);
        // duplicate: REST 409 (was an unhandled 500) / DATA_PERMISSION_ALREADY_EXISTS
        (await client.PostAsJsonAsync(TenantApiUrl("dataPermissions"), new DataPermissionDto { PermissionId = methodId },
            ct)).StatusCode.Should().Be(HttpStatusCode.Conflict);

        var policy = new DataPolicyDto
        {
            TargetCkTypeIds = ["Test.Wave2/Thing"], Actions = ["Read"], Scope = "OwnedOnly", EnforcementMode = "AuditOnly"
        };
        var restPolicy = await client.PostAsJsonAsync(TenantApiUrl($"dataPermissions/{restId}/policies"), policy, ct);
        restPolicy.StatusCode.Should().Be(HttpStatusCode.OK);
        var restPolicyRtId = (await restPolicy.Content.ReadAsStringAsync(ct)).Trim('"');
        var methodPermission = await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s =>
            s.FindByPermissionIdAsync(methodId));
        var methodPolicy = await DispatchAsync(host, admin, SystemIdentityCkIds.DataPermissionCreatePolicyMethodId,
            IdentityMethodFacade.DataPermissionCkTypeId, methodPermission!.RtId.ToString(),
            new DataPermissionCreatePolicyParameters
            {
                TargetCkTypeIds = ["Test.Wave2/Thing"], Actions = ["Read"], Scope = RtDataPolicyScopeEnum.OwnedOnly,
                EnforcementMode = RtDataPolicyEnforcementModeEnum.AuditOnly
            });
        methodPolicy.Success.Should().BeTrue(methodPolicy.Error?.Code);

        var restPolicies = await WithStoreAsync<IDataPermissionStore, IReadOnlyList<RtDataPolicy>>(async s =>
            await s.GetPoliciesAsync((await s.FindByPermissionIdAsync(restId))!.RtId));
        var methodPolicies =
            await WithStoreAsync<IDataPermissionStore, IReadOnlyList<RtDataPolicy>>(s => s.GetPoliciesAsync(methodPermission.RtId));
        foreach (var stored in new[] { restPolicies.Single(), methodPolicies.Single() })
        {
            stored.TargetCkTypeIds.Should().Equal("Test.Wave2/Thing");
            stored.Actions.Should().Equal("Read");
            stored.Scope.Should().Be(RtDataPolicyScopeEnum.OwnedOnly);
            stored.EnforcementMode.Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
        }

        restPolicies.Single().RtId.ToString().Should().Be(restPolicyRtId);
        (await client.PostAsJsonAsync(TenantApiUrl($"dataPermissions/{NewName("none")}/policies"), policy, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);

        // delete the policy (REST) and the permission with its policies (method)
        (await client.DeleteAsync(TenantApiUrl($"dataPermissions/policies/{restPolicyRtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.DataPermissionDeleteDataPermissionMethodId,
            IdentityMethodFacade.DataPermissionCkTypeId, methodPermission.RtId.ToString(),
            new DataPermissionDeleteDataPermissionParameters())).Success.Should().BeTrue();
        (await client.DeleteAsync(TenantApiUrl($"dataPermissions/{restId}"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s => s.FindByPermissionIdAsync(restId))).Should()
            .BeNull();
        (await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s => s.FindByPermissionIdAsync(methodId))).Should()
            .BeNull();
        (await client.DeleteAsync(TenantApiUrl($"dataPermissions/{restId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Client_RestAndTheMethod_StoreTheSameClient_WithTheServerDefaults_AndTheSecretOnlyAsAHash()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement, SecretManagement).Client(host);
        var admin = Admin(TenantManagement, SecretManagement);
        var ct = TestContext.Current.CancellationToken;
        var restId = NewName("c");
        var methodId = NewName("c");
        var secret = $"client-secret-{Guid.NewGuid():N}";

        var rest = await client.PostAsJsonAsync(TenantApiUrl("clients"), ClientDto(restId, secret), ct);
        rest.StatusCode.Should().Be(HttpStatusCode.OK, await rest.Content.ReadAsStringAsync(ct));
        var created = await DispatchAsync(host, admin, SystemIdentityCkIds.ClientCreateClientMethodId,
            IdentityMethodFacade.ClientCkTypeId, null, ClientParameters(methodId, secret));
        created.Success.Should().BeTrue(created.Error?.Code);
        created.ResultJson.Should().NotContain(secret);

        var restStored = await FindClientAsync(restId);
        var methodStored = await FindClientAsync(methodId);
        foreach (var stored in new[] { restStored!, methodStored! })
        {
            stored.RequirePkce.Should().BeTrue("server-side default of a new client");
            stored.AccessTokenType.Should().Be(RtTokenTypeEnum.Jwt);
            stored.AllowAccessTokensViaBrowser.Should().BeTrue();
            stored.AlwaysIncludeUserClaimsInIdToken.Should().BeTrue();
            stored.RequireConsent.Should().BeFalse();
            stored.ClientName.Should().Be("A client");
            stored.AllowedGrantTypes.Should().Equal("client_credentials");
            stored.AllowedScopes.Should().Contain("openid", "the octo default scopes").And.Contain("custom_scope");
            stored.RedirectUris.Select(u => (u.Uri, u.Source)).Should().Equal(("https://app.example.test/cb", "api"));
            stored.ClientSecrets.Should().ContainSingle().Which.Value.Should().NotBe(secret, "stored as a hash");
        }

        AllEventText().Should().NotContain(secret);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ClientCreateClientMethodId, IdentityMethodFacade.ClientCkTypeId,
            null, ClientParameters(methodId, null))).Error!.Code.Should().Be(ClientCrudErrors.ClientAlreadyExists);
        (await client.PostAsJsonAsync(TenantApiUrl("clients"), ClientDto(methodId, null), ct)).StatusCode.Should()
            .Be(HttpStatusCode.Conflict);

        // update: REST and the method; a secret replaces the secrets
        (await client.PutAsJsonAsync(TenantApiUrl($"clients/{restId}"), new ClientDto { ClientName = "Renamed" }, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ClientUpdateClientMethodId, IdentityMethodFacade.ClientCkTypeId,
            methodStored!.RtId.ToString(), new ClientUpdateClientParameters { ClientName = "Renamed" })).Success.Should()
            .BeTrue();
        (await FindClientAsync(restId))!.ClientName.Should().Be("Renamed");
        (await FindClientAsync(methodId))!.ClientName.Should().Be("Renamed");
        (await FindClientAsync(methodId))!.ClientSecrets.Should().ContainSingle("an update without a secret keeps it");
        (await FindClientAsync(methodId))!.AllowedScopes.Should().Contain("custom_scope",
            "an update without allowedScopes keeps the scopes on the method path");
        (await FindClientAsync(restId))!.AllowedScopes.Should().NotContain("custom_scope",
            "REST resets the scopes to the octo defaults when the body has none, as before");

        // delete: REST and the method; unknown = 404 / not found
        (await client.DeleteAsync(TenantApiUrl($"clients/{restId}"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ClientDeleteClientMethodId, IdentityMethodFacade.ClientCkTypeId,
            methodStored.RtId.ToString(), new ClientDeleteClientParameters())).Success.Should().BeTrue();
        (await FindClientAsync(restId)).Should().BeNull();
        (await FindClientAsync(methodId)).Should().BeNull();
        (await client.DeleteAsync(TenantApiUrl($"clients/{restId}"), ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task AClientSecret_WithoutSecretManagement_IsRefused_OnRestAndTheMethod_AndNothingIsCreated()
    {
        var host = Host(secretRoleEnforcement: "Enforce");
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var restId = NewName("c");
        var methodId = NewName("c");

        (await client.PostAsJsonAsync(TenantApiUrl("clients"), ClientDto(restId, "s3cret-value"),
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var refused = await DispatchAsync(host, Admin(TenantManagement), SystemIdentityCkIds.ClientCreateClientMethodId,
            IdentityMethodFacade.ClientCkTypeId, null, ClientParameters(methodId, "s3cret-value"));
        refused.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        refused.Error.Parameters.Should().Contain("requiredRole", SecretManagement);

        (await FindClientAsync(restId)).Should().BeNull();
        (await FindClientAsync(methodId)).Should().BeNull();
        var withoutSecret = await DispatchAsync(host, Admin(TenantManagement), SystemIdentityCkIds.ClientCreateClientMethodId,
            IdentityMethodFacade.ClientCkTypeId, null, ClientParameters(methodId, null));
        withoutSecret.Success.Should().BeTrue("without a secret TenantManagement is enough, as on REST ({0} {1})",
            withoutSecret.Error?.Code, JsonSerializer.Serialize(withoutSecret.Error?.Parameters));
    }

    [Fact]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingIsCreated()
    {
        var host = Host(enforceTenantGate: true);
        var foreign = new CkMethodPrincipal(Guid.NewGuid().ToString("N"),
            [UserManagement, TenantManagement, SecretManagement], ["octo_api"])
        {
            IsFromAccessToken = true, TokenTenantId = "othertenantcf"
        };
        var providerName = NewName("g");
        var pattern = NewName("d");
        var permissionId = NewName("dp");
        var clientId = NewName("c");

        var refusals = new[]
        {
            await DispatchAsync(host, foreign, SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
                GoogleCkTypeId, null, GoogleParameters(providerName, "s")),
            await DispatchAsync(host, foreign, SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId,
                IdentityMethodFacade.EmailDomainGroupRuleCkTypeId, null,
                new EmailDomainGroupRuleCreateEmailDomainGroupRuleParameters { EmailDomainPattern = pattern, TargetGroupRtId = "g" }),
            await DispatchAsync(host, foreign, SystemIdentityCkIds.DataPermissionCreateDataPermissionMethodId,
                IdentityMethodFacade.DataPermissionCkTypeId, null,
                new DataPermissionCreateDataPermissionParameters { PermissionId = permissionId }),
            await DispatchAsync(host, foreign, SystemIdentityCkIds.ClientCreateClientMethodId,
                IdentityMethodFacade.ClientCkTypeId, null, ClientParameters(clientId, null))
        };

        foreach (var refusal in refusals)
        {
            refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
            refusal.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        }

        using var client = (FacadeCaller.User(UserManagement, TenantManagement) with { TokenTenant = "othertenantcf" })
            .Client(host);
        (await client.PostAsJsonAsync(TenantApiUrl("clients"), ClientDto(clientId, null),
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        (await WithStoreAsync<IOctoIdentityProviderStore, RtIdentityProvider?>(s => s.GetByNameAsync(providerName))).Should()
            .BeNull();
        (await WithStoreAsync<IEmailDomainGroupRuleStore, RtEmailDomainGroupRule?>(s => s.GetByDomainPatternAsync(pattern)))
            .Should().BeNull();
        (await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s => s.FindByPermissionIdAsync(permissionId))).Should()
            .BeNull();
        (await FindClientAsync(clientId)).Should().BeNull();
    }

    [Fact]
    public async Task ACallerWhoMayNotWriteTheType_IsRefusedOnEveryCreate_AndNothingIsCreated()
    {
        var host = Host(denyReads: true);
        using var client = FacadeCaller.User(UserManagement, TenantManagement, SecretManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        IdentityProviderDto provider = GoogleDto(NewName("g"), "s");
        var pattern = NewName("d");
        var permissionId = NewName("dp");
        var clientId = NewName("c");

        (await client.PostAsJsonAsync(TenantApiUrl("identityProviders"), provider, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await client.PostAsJsonAsync(TenantApiUrl("emailDomainGroupRules"), RuleDto(pattern), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await client.PostAsJsonAsync(TenantApiUrl("dataPermissions"), new DataPermissionDto { PermissionId = permissionId },
            ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PostAsJsonAsync(TenantApiUrl("clients"), ClientDto(clientId, null), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);

        (await WithStoreAsync<IOctoIdentityProviderStore, RtIdentityProvider?>(s => s.GetByNameAsync(provider.Name!)))
            .Should().BeNull();
        (await WithStoreAsync<IEmailDomainGroupRuleStore, RtEmailDomainGroupRule?>(s => s.GetByDomainPatternAsync(pattern)))
            .Should().BeNull();
        (await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s => s.FindByPermissionIdAsync(permissionId))).Should()
            .BeNull();
        (await FindClientAsync(clientId)).Should().BeNull();
    }

    public static TheoryData<string, string> MethodPathRefusals
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (var name in EndpointNames)
            {
                data.Add(name, "CommunicationManagement");
                data.Add(name, NoOctoApiScope);
                if (name is "updateMapping" or "deleteMapping" or "createPermission" or "deletePermission" or
                    "createPolicy" or "deletePolicy")
                {
                    data.Add(name, TenantManagement);
                }
            }

            return data;
        }
    }

    private const string NoOctoApiScope = "UserManagement+TenantManagement without octo_api";

    [Theory]
    [MemberData(nameof(MethodPathRefusals))]
    public async Task TheMethodPath_RefusesACallerWithoutTheDeclaredRoleOrScope_AndChangesNothing(string endpoint,
        string callerKind)
    {
        var host = Host();
        var caller = callerKind == NoOctoApiScope
            ? new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement, TenantManagement], [])
            : Admin(callerKind);
        var call = await PrepareMethodCallAsync(endpoint);

        var response = await DispatchAsync(host, caller, call.MethodId, call.CkTypeId, call.TargetRtId, call.Parameters);

        response.Success.Should().BeFalse($"{endpoint} by {callerKind}");
        response.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden, $"{endpoint} by {callerKind}");
        await call.AssertUnchanged();
    }

    [Fact]
    public void TheCrudMethods_RunInThisProcess()
    {
        var transport = Host().Services.GetRequiredService<ICkInProcessMethodTransport>();

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
                     SystemIdentityCkIds.IdentityProviderUpdateIdentityProviderMethodId,
                     SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId,
                     SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId,
                     SystemIdentityCkIds.EmailDomainGroupRuleUpdateEmailDomainGroupRuleMethodId,
                     SystemIdentityCkIds.EmailDomainGroupRuleDeleteEmailDomainGroupRuleMethodId,
                     SystemIdentityCkIds.ExternalTenantUserMappingUpdateMappingMethodId,
                     SystemIdentityCkIds.ExternalTenantUserMappingDeleteMappingMethodId,
                     SystemIdentityCkIds.DataPermissionCreateDataPermissionMethodId,
                     SystemIdentityCkIds.DataPermissionDeleteDataPermissionMethodId,
                     SystemIdentityCkIds.DataPermissionCreatePolicyMethodId,
                     SystemIdentityCkIds.DataPolicyDeleteDataPolicyMethodId,
                     SystemIdentityCkIds.ClientCreateClientMethodId, SystemIdentityCkIds.ClientUpdateClientMethodId,
                     SystemIdentityCkIds.ClientDeleteClientMethodId
                 })
        {
            transport.CanHandle(methodId).Should().BeTrue(methodId);
        }
    }

    #region Helpers

    private WebApplicationFactory<Program> Host(bool enforceTenantGate = false, bool denyReads = false,
        string? secretRoleEnforcement = null)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            // The secret-carrying methods (provider and client create/update) are offered on the bus, so the dispatcher
            // reaches them as the GraphQL gateway would; with the switch off they are local only (REST facade only).
            b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
            if (enforceTenantGate)
            {
                b.UseSetting("TenantAuthorization:UserTokenEnforcement", "Enforce");
            }

            if (secretRoleEnforcement != null)
            {
                b.UseSetting("IdentityApiAuthorization:SecretManagementRoleEnforcement", secretRoleEnforcement);
            }

            b.ConfigureTestServices(services =>
            {
                services.AddSingleton(_audit.Events);
                services.AddSingleton<ICkInProcessAmbientStateProbe>(_probe);
                services.AddSingleton<IStartupFilter, MarkRequestsStartupFilter>();
                if (denyReads)
                {
                    services.AddSingleton(DenyEverything());
                }
            });
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>An enforcing data policy that lets the caller see nothing: no entity and no type.</summary>
    private static IRtDataPermissionEvaluator DenyEverything()
    {
        var evaluator = FacadeDataPolicy.DenyAllReads();
        evaluator.EvaluateTypeAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(),
                Arg.Any<RtCkId<CkTypeId>>(), Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new RtDataPermissionVerdict(RtDataPermissionDecision.NotVisible, RtDataPermissionReason.NoGrant));
        return evaluator;
    }

    private static CkMethodPrincipal Admin(params string[] roles) => new(Guid.NewGuid().ToString("N"), roles, ["octo_api"]);

    private string AllEventText() => JsonSerializer.Serialize(_audit.All);

    private sealed record EndpointCall(HttpResponseMessage Response, string MethodId, HttpStatusCode Expected);

    /// <summary>Calls one of the fifteen endpoints with a valid change on fresh entities.</summary>
    private async Task<EndpointCall> CallAsync(HttpClient client, string endpoint)
    {
        var ct = TestContext.Current.CancellationToken;
        switch (endpoint)
        {
            case "createProvider":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("identityProviders"),
                        (IdentityProviderDto)GoogleDto(NewName("g"), "s"), ct),
                    SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId, HttpStatusCode.OK);
            case "updateProvider":
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"identityProviders/{await NewProviderAsync()}"),
                        (IdentityProviderDto)GoogleDto(NewName("g"), null), ct),
                    SystemIdentityCkIds.IdentityProviderUpdateIdentityProviderMethodId, HttpStatusCode.OK);
            case "deleteProvider":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"identityProviders/{await NewProviderAsync()}"), ct),
                    SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId, HttpStatusCode.OK);
            case "createRule":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("emailDomainGroupRules"),
                        RuleDto(NewName("d")), ct),
                    SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId, HttpStatusCode.Created);
            case "updateRule":
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"emailDomainGroupRules/{await NewRuleAsync()}"),
                        RuleDto(NewName("d")), ct),
                    SystemIdentityCkIds.EmailDomainGroupRuleUpdateEmailDomainGroupRuleMethodId, HttpStatusCode.OK);
            case "deleteRule":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"emailDomainGroupRules/{await NewRuleAsync()}"), ct),
                    SystemIdentityCkIds.EmailDomainGroupRuleDeleteEmailDomainGroupRuleMethodId, HttpStatusCode.OK);
            case "updateMapping":
                return new EndpointCall(await client.PutAsJsonAsync(
                        TenantApiUrl($"externalTenantUserMappings/{(await NewMappingAsync()).RtId}"),
                        new UpdateExternalTenantUserMappingDto { RoleIds = [] }, ct),
                    SystemIdentityCkIds.ExternalTenantUserMappingUpdateMappingMethodId, HttpStatusCode.OK);
            case "deleteMapping":
                return new EndpointCall(await client.DeleteAsync(
                        TenantApiUrl($"externalTenantUserMappings/{(await NewMappingAsync()).RtId}"), ct),
                    SystemIdentityCkIds.ExternalTenantUserMappingDeleteMappingMethodId, HttpStatusCode.OK);
            case "createPermission":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("dataPermissions"),
                        new DataPermissionDto { PermissionId = NewName("dp") }, ct),
                    SystemIdentityCkIds.DataPermissionCreateDataPermissionMethodId, HttpStatusCode.OK);
            case "deletePermission":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"dataPermissions/{await NewPermissionAsync()}"), ct),
                    SystemIdentityCkIds.DataPermissionDeleteDataPermissionMethodId, HttpStatusCode.OK);
            case "createPolicy":
                return new EndpointCall(await client.PostAsJsonAsync(
                        TenantApiUrl($"dataPermissions/{await NewPermissionAsync()}/policies"),
                        new DataPolicyDto { TargetCkTypeIds = ["Test.Wave2/Thing"], EnforcementMode = "AuditOnly" }, ct),
                    SystemIdentityCkIds.DataPermissionCreatePolicyMethodId, HttpStatusCode.OK);
            case "deletePolicy":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"dataPermissions/policies/{await NewPolicyAsync()}"), ct),
                    SystemIdentityCkIds.DataPolicyDeleteDataPolicyMethodId, HttpStatusCode.OK);
            case "createClient":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("clients"), ClientDto(NewName("c"), null), ct),
                    SystemIdentityCkIds.ClientCreateClientMethodId, HttpStatusCode.OK);
            case "updateClient":
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"clients/{(await NewClientAsync()).ClientId}"),
                        new ClientDto { ClientName = "Renamed" }, ct),
                    SystemIdentityCkIds.ClientUpdateClientMethodId, HttpStatusCode.OK);
            default:
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"clients/{(await NewClientAsync()).ClientId}"), ct),
                    SystemIdentityCkIds.ClientDeleteClientMethodId, HttpStatusCode.OK);
        }
    }

    private sealed record MethodCall(string MethodId, string CkTypeId, string? TargetRtId, object Parameters,
        Func<Task> AssertUnchanged);

    /// <summary>
    ///     One of the fifteen methods with a valid change on fresh entities, as the GraphQL gateway sends it, and the check that
    ///     nothing was written (no created entity, the target unchanged or still there).
    /// </summary>
    private async Task<MethodCall> PrepareMethodCallAsync(string endpoint)
    {
        var newName = NewName("mp");
        switch (endpoint)
        {
            case "createProvider":
                return new MethodCall(SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId, GoogleCkTypeId, null,
                    GoogleParameters(newName, "s"),
                    async () => (await WithStoreAsync<IOctoIdentityProviderStore, RtIdentityProvider?>(s =>
                        s.GetByNameAsync(newName))).Should().BeNull());
            case "updateProvider":
            case "deleteProvider":
            {
                var rtId = await NewProviderAsync();
                return new MethodCall(
                    endpoint == "updateProvider"
                        ? SystemIdentityCkIds.IdentityProviderUpdateIdentityProviderMethodId
                        : SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId, GoogleCkTypeId, rtId.ToString(),
                    endpoint == "updateProvider"
                        ? GoogleUpdateParameters(newName)
                        : new IdentityProviderDeleteIdentityProviderParameters(),
                    async () => (await WithStoreAsync<IOctoIdentityProviderStore, RtIdentityProvider?>(s =>
                        s.GetByIdAsync(rtId)))!.Name.Should().NotBe(newName));
            }
            case "createRule":
                return new MethodCall(SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId,
                    IdentityMethodFacade.EmailDomainGroupRuleCkTypeId, null,
                    new EmailDomainGroupRuleCreateEmailDomainGroupRuleParameters
                    {
                        EmailDomainPattern = newName, TargetGroupRtId = "g"
                    },
                    async () => (await WithStoreAsync<IEmailDomainGroupRuleStore, RtEmailDomainGroupRule?>(s =>
                        s.GetByDomainPatternAsync(newName))).Should().BeNull());
            case "updateRule":
            case "deleteRule":
            {
                var rtId = await NewRuleAsync();
                return new MethodCall(
                    endpoint == "updateRule"
                        ? SystemIdentityCkIds.EmailDomainGroupRuleUpdateEmailDomainGroupRuleMethodId
                        : SystemIdentityCkIds.EmailDomainGroupRuleDeleteEmailDomainGroupRuleMethodId,
                    IdentityMethodFacade.EmailDomainGroupRuleCkTypeId, rtId.ToString(),
                    endpoint == "updateRule"
                        ? new EmailDomainGroupRuleUpdateEmailDomainGroupRuleParameters
                        {
                            EmailDomainPattern = newName, TargetGroupRtId = "g"
                        }
                        : new EmailDomainGroupRuleDeleteEmailDomainGroupRuleParameters(),
                    async () => (await WithStoreAsync<IEmailDomainGroupRuleStore, RtEmailDomainGroupRule?>(s =>
                        s.GetByIdAsync(rtId)))!.EmailDomainPattern.Should().NotBe(newName));
            }
            case "updateMapping":
            case "deleteMapping":
            {
                var mapping = await NewMappingAsync();
                return new MethodCall(
                    endpoint == "updateMapping"
                        ? SystemIdentityCkIds.ExternalTenantUserMappingUpdateMappingMethodId
                        : SystemIdentityCkIds.ExternalTenantUserMappingDeleteMappingMethodId,
                    IdentityMethodFacade.ExternalTenantUserMappingCkTypeId, mapping.RtId.ToString(),
                    endpoint == "updateMapping"
                        ? new ExternalTenantUserMappingUpdateMappingParameters { RoleIds = [newName] }
                        : new ExternalTenantUserMappingDeleteMappingParameters(),
                    async () => (await WithStoreAsync<IExternalTenantUserMappingStore, RtExternalTenantUserMapping?>(s =>
                        s.GetByIdAsync(mapping.RtId)))!.MappedRoleIds?.ToList().Should().NotContain(newName));
            }
            case "createPermission":
                return new MethodCall(SystemIdentityCkIds.DataPermissionCreateDataPermissionMethodId,
                    IdentityMethodFacade.DataPermissionCkTypeId, null,
                    new DataPermissionCreateDataPermissionParameters { PermissionId = newName },
                    async () => (await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s =>
                        s.FindByPermissionIdAsync(newName))).Should().BeNull());
            case "deletePermission":
            case "createPolicy":
            {
                var permissionId = await NewPermissionAsync();
                var permission =
                    await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s => s.FindByPermissionIdAsync(permissionId));
                return new MethodCall(
                    endpoint == "deletePermission"
                        ? SystemIdentityCkIds.DataPermissionDeleteDataPermissionMethodId
                        : SystemIdentityCkIds.DataPermissionCreatePolicyMethodId,
                    IdentityMethodFacade.DataPermissionCkTypeId, permission!.RtId.ToString(),
                    endpoint == "deletePermission"
                        ? new DataPermissionDeleteDataPermissionParameters()
                        : new DataPermissionCreatePolicyParameters
                        {
                            TargetCkTypeIds = ["Test.Wave2/Thing"], Scope = RtDataPolicyScopeEnum.All,
                            EnforcementMode = RtDataPolicyEnforcementModeEnum.AuditOnly
                        },
                    async () =>
                    {
                        (await WithStoreAsync<IDataPermissionStore, RtDataPermission?>(s =>
                            s.FindByPermissionIdAsync(permissionId))).Should().NotBeNull();
                        (await WithStoreAsync<IDataPermissionStore, IReadOnlyList<RtDataPolicy>>(s =>
                            s.GetPoliciesAsync(permission.RtId))).Should().BeEmpty();
                    });
            }
            case "deletePolicy":
            {
                var policyRtId = await NewPolicyAsync();
                return new MethodCall(SystemIdentityCkIds.DataPolicyDeleteDataPolicyMethodId,
                    IdentityMethodFacade.DataPolicyCkTypeId, policyRtId, new DataPolicyDeleteDataPolicyParameters(),
                    async () => (await LoadAsync<RtDataPolicy>(OctoObjectId.Parse(policyRtId))).Should().NotBeNull());
            }
            case "createClient":
                return new MethodCall(SystemIdentityCkIds.ClientCreateClientMethodId, IdentityMethodFacade.ClientCkTypeId, null,
                    ClientParameters(newName, null), async () => (await FindClientAsync(newName)).Should().BeNull());
            default:
            {
                var stored = await NewClientAsync();
                return new MethodCall(
                    endpoint == "updateClient"
                        ? SystemIdentityCkIds.ClientUpdateClientMethodId
                        : SystemIdentityCkIds.ClientDeleteClientMethodId,
                    IdentityMethodFacade.ClientCkTypeId, stored.RtId.ToString(),
                    endpoint == "updateClient"
                        ? new ClientUpdateClientParameters { ClientName = newName }
                        : new ClientDeleteClientParameters(),
                    async () => (await FindClientAsync(stored.ClientId))!.ClientName.Should().NotBe(newName));
            }
        }
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string methodId, string ckTypeId, string? targetRtId, object parameters)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = TestHostMethodDeadlineFloor.DeadlineFromNow()
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private static GoogleIdentityProviderDto GoogleDto(string name, string? secret) => new()
    {
        Name = name, IsEnabled = true, AllowSelfRegistration = false, Description = "A provider",
        ClientId = "google-client", ClientSecret = secret
    };

    private static IdentityProviderCreateIdentityProviderParameters GoogleParameters(string name, string secret) => new()
    {
        Name = name, Enabled = true, AllowSelfRegistration = false, Description = "A provider", ClientId = "google-client",
        ClientSecret = secret
    };

    private static IdentityProviderUpdateIdentityProviderParameters GoogleUpdateParameters(string name) => new()
    {
        Name = name, Enabled = true, AllowSelfRegistration = false, Description = "A provider", ClientId = "google-client"
    };

    private static EmailDomainGroupRuleDto RuleDto(string pattern) => new()
    {
        EmailDomainPattern = pattern, TargetGroupRtId = OctoObjectId.GenerateNewId().ToString(), Description = "A rule"
    };

    private static ClientDto ClientDto(string clientId, string? secret) => new()
    {
        ClientId = clientId, ClientName = "A client", AllowedGrantTypes = ["client_credentials"],
        RedirectUris = ["https://app.example.test/cb"], AllowedScopes = ["custom_scope"], ClientSecret = secret,
        RequireClientSecret = secret != null, IsEnabled = true
    };

    private static ClientCreateClientParameters ClientParameters(string clientId, string? secret) => new()
    {
        ClientId = clientId, ClientName = "A client", AllowedGrantTypes = ["client_credentials"],
        RedirectUris = ["https://app.example.test/cb"], AllowedScopes = ["custom_scope"], ClientSecret = secret,
        RequireClientSecret = secret != null
    };

    private async Task<OctoObjectId> NewProviderAsync()
    {
        var provider = new RtGoogleIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = NewName("gp"), IsEnabled = true, ClientId = "google-client",
            ClientSecret = RtSecretValue.Pending("seeded-secret")
        };
        await WithStoreAsync<IOctoIdentityProviderStore, bool>(async s =>
        {
            await s.StoreAsync(provider);
            return true;
        });
        return provider.RtId;
    }

    private async Task<OctoObjectId> NewRuleAsync()
    {
        var rule = new RtEmailDomainGroupRule
        {
            RtId = OctoObjectId.GenerateNewId(), EmailDomainPattern = NewName("dr"), TargetGroupRtId = "g"
        };
        await WithStoreAsync<IEmailDomainGroupRuleStore, bool>(async s =>
        {
            await s.StoreAsync(rule);
            return true;
        });
        return rule.RtId;
    }

    private async Task<RtExternalTenantUserMapping> NewMappingAsync()
    {
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(), SourceTenantId = "sourcetenant", SourceUserId = Guid.NewGuid().ToString("N"),
            SourceUserName = NewName("u")
        };
        await WithStoreAsync<IExternalTenantUserMappingStore, bool>(async s =>
        {
            await s.StoreAsync(mapping);
            return true;
        });
        return mapping;
    }

    private async Task<string> NewPermissionAsync()
    {
        var permissionId = NewName("dpn");
        await WithStoreAsync<IDataPermissionStore, OctoObjectId>(s => s.CreateAsync(permissionId, null));
        return permissionId;
    }

    private async Task<string> NewPolicyAsync()
    {
        var permissionId = await NewPermissionAsync();
        var rtId = await WithStoreAsync<IDataPermissionStore, OctoObjectId>(s => s.CreatePolicyAsync(permissionId,
            ["Test.Wave2/Thing"], [], RtDataPolicyScopeEnum.All, RtDataPolicyEnforcementModeEnum.AuditOnly));
        return rtId.ToString();
    }

    private async Task<RtClient> NewClientAsync()
    {
        var client = ClientChange.NewClient();
        new ClientChange(NewName("cc"), true, "Client", null, ["client_credentials"], null, null, null, null, null, null,
            null, null, null, null, null, null).ApplyTo(client, isCreate: true);
        await WithStoreAsync<IOctoClientStore, bool>(async s =>
        {
            await s.CreateAsync(client);
            return true;
        });
        return (await FindClientAsync(client.ClientId))!;
    }

    private Task<RtClient?> FindClientAsync(string clientId) =>
        WithStoreAsync<IOctoClientStore, RtClient?>(s => s.FindRtClientByIdAsync(clientId));

    private async Task<T?> LoadAsync<T>(OctoObjectId rtId) where T : RtEntity, new()
    {
        using var scope = CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var entity = await repository.GetRtEntityByRtIdAsync<T>(session, rtId);
        await session.CommitTransactionAsync();
        return entity;
    }

    private async Task<TResult> WithStoreAsync<TStore, TResult>(Func<TStore, Task<TResult>> action) where TStore : notnull
    {
        using var scope = CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<TStore>());
    }

    #endregion
}
