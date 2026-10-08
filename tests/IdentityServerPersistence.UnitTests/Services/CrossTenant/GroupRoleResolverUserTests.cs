using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.CrossTenant;

/// <summary>
///     AB#5708: a cross-tenant shadow user's effective roles include the roles of the groups its
///     external tenant user mapping is a member of and the mapping's MappedRoleIds — resolved on
///     every call, not snapshotted onto the user.
/// </summary>
public class GroupRoleResolverUserTests
{
    private readonly IGroupStore _groupStore = Substitute.For<IGroupStore>();
    private readonly IExternalTenantUserMappingStore _mappingStore = Substitute.For<IExternalTenantUserMappingStore>();
    private readonly RegisteredTenantsShadowUserChainResolver _registry = new("meshmakers", "karlplus");
    private readonly GroupRoleResolver _sut;

    private readonly Dictionary<OctoObjectId, List<string>> _members = new();
    private readonly Dictionary<OctoObjectId, List<string>> _groupRoles = new();
    private readonly List<RtGroup> _groups = [];

    public GroupRoleResolverUserTests()
    {
        _groupStore.GetAllAsync().Returns(_ => _groups.AsEnumerable());
        _groupStore.GetAllMemberSubjectIdsAsync(Arg.Any<OctoObjectId>())
            .Returns(ci => (IReadOnlyList<string>)(_members.GetValueOrDefault(ci.Arg<OctoObjectId>()) ?? []));
        _groupStore.GetRoleIdsAsync(Arg.Any<OctoObjectId>())
            .Returns(ci => (IReadOnlyList<string>)(_groupRoles.GetValueOrDefault(ci.Arg<OctoObjectId>()) ?? []));
        _groupStore.GetMemberGroupIdsAsync(Arg.Any<OctoObjectId>()).Returns((IReadOnlyList<string>)[]);
        _mappingStore.FindBySourceUserNamesAsync(Arg.Any<IReadOnlyCollection<(string, string)>>())
            .Returns(Array.Empty<RtExternalTenantUserMapping>());

        _sut = new GroupRoleResolver(_groupStore, _mappingStore, _registry);
    }

    [Fact]
    public async Task ShadowUser_MappingInGroup_ReceivesGroupRoles()
    {
        var userId = NewId();
        var mapping = Mapping("meshmakers", "gerald");
        var role = NewId();
        AddGroup(role, mapping.RtId.ToString());
        ReturnMappings(mapping);

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(userId, "xt_meshmakers_gerald");

        roles.Should().BeEquivalentTo([role]);
    }

    [Fact]
    public async Task ShadowUser_RoleAddedToGroupLater_IsEffectiveOnNextResolution()
    {
        var mapping = Mapping("meshmakers", "gerald");
        var initialRole = NewId();
        var group = AddGroup(initialRole, mapping.RtId.ToString());
        ReturnMappings(mapping);

        (await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_meshmakers_gerald"))
            .Should().BeEquivalentTo([initialRole]);

        var blueprintRole = NewId();
        _groupRoles[group.RtId].Add(blueprintRole);

        (await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_meshmakers_gerald"))
            .Should().BeEquivalentTo([initialRole, blueprintRole]);
    }

    [Fact]
    public async Task ShadowUser_MappedRoleIds_AreIncluded_InvalidIdsSkipped()
    {
        var mappedRole = NewId();
        var mapping = Mapping("meshmakers", "gerald", mappedRole, "not-a-role-id");
        ReturnMappings(mapping);

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_meshmakers_gerald");

        roles.Should().BeEquivalentTo([mappedRole]);
    }

    [Fact]
    public async Task NestedShadowUser_LooksUpMappingsForEveryTier()
    {
        await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_karlplus_xt_meshmakers_gerald");

        await _mappingStore.Received(1).FindBySourceUserNamesAsync(
            Arg.Is<IReadOnlyCollection<(string, string)>>(c =>
                c.Count == 2 &&
                HasIdentity(c, "karlplus", "xt_meshmakers_gerald") &&
                HasIdentity(c, "meshmakers", "gerald")));
    }

    [Fact]
    public async Task UserAndMappingGroups_AreUnited()
    {
        var userId = NewId();
        var mapping = Mapping("meshmakers", "gerald");
        var userRole = NewId();
        var mappingRole = NewId();
        AddGroup(userRole, userId);
        AddGroup(mappingRole, mapping.RtId.ToString());
        ReturnMappings(mapping);

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(userId, "xt_meshmakers_gerald");

        roles.Should().BeEquivalentTo([userRole, mappingRole]);
    }

    [Fact]
    public async Task LocalUser_NeverQueriesMappings()
    {
        var userId = NewId();
        var role = NewId();
        AddGroup(role, userId);

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(userId, "gerald");

        roles.Should().BeEquivalentTo([role]);
        await _mappingStore.DidNotReceive()
            .FindBySourceUserNamesAsync(Arg.Any<IReadOnlyCollection<(string, string)>>());
    }

    [Fact]
    public async Task OtherMappingsGroups_DoNotLeak()
    {
        var foreignMapping = Mapping("meshmakers", "someoneelse");
        AddGroup(NewId(), foreignMapping.RtId.ToString());

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_meshmakers_gerald");

        roles.Should().BeEmpty();
    }

    // --- AB#5708 review: tenant ids may contain '_' — the name chain must not be spoofable ---

    [Fact]
    public async Task UnderscoreTenant_OrdinaryUserCannotUnwindToForeignIdentity()
    {
        // Tenant "evil_xt" + ordinary user "meshmakers_gerald" → shadow "xt_evil_xt_meshmakers_gerald",
        // which a naive split reads as (evil, xt_meshmakers_gerald) → (meshmakers, gerald).
        _registry.Register("evil_xt");

        await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_evil_xt_meshmakers_gerald");

        await _mappingStore.Received(1).FindBySourceUserNamesAsync(
            Arg.Is<IReadOnlyCollection<(string, string)>>(c =>
                c.Count == 1 && HasIdentity(c, "evil_xt", "meshmakers_gerald")));
    }

    [Fact]
    public async Task UnderscoreTenant_TenantIdWithXtSegment_CannotUnwindToForeignIdentity()
    {
        // Tenant "evil_xt_meshmakers" + ordinary user "gerald" → the same spoofable name shape.
        _registry.Register("evil_xt_meshmakers");

        await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_evil_xt_meshmakers_gerald");

        await _mappingStore.Received(1).FindBySourceUserNamesAsync(
            Arg.Is<IReadOnlyCollection<(string, string)>>(c =>
                c.Count == 1 && HasIdentity(c, "evil_xt_meshmakers", "gerald")));
    }

    [Fact]
    public async Task UnderscoreTenant_OwnMappingIsFound()
    {
        _registry.Register("tenant_a");
        var mapping = Mapping("tenant_a", "gerald");
        var role = NewId();
        AddGroup(role, mapping.RtId.ToString());
        ReturnMappings(mapping);

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_tenant_a_gerald");

        roles.Should().BeEquivalentTo([role]);
        await _mappingStore.Received(1).FindBySourceUserNamesAsync(
            Arg.Is<IReadOnlyCollection<(string, string)>>(c =>
                c.Count == 1 && HasIdentity(c, "tenant_a", "gerald")));
    }

    [Fact]
    public async Task AmbiguousTenantPrefix_FailsClosed()
    {
        // Both "evil" and "evil_xt" exist: the name cannot be attributed, so it grants nothing.
        _registry.Register("evil", "evil_xt");
        ReturnMappings(Mapping("meshmakers", "gerald", NewId()));

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_evil_xt_meshmakers_gerald");

        roles.Should().BeEmpty();
        await _mappingStore.DidNotReceive()
            .FindBySourceUserNamesAsync(Arg.Any<IReadOnlyCollection<(string, string)>>());
    }

    [Fact]
    public async Task UnregisteredTenant_FailsClosed()
    {
        ReturnMappings(Mapping("deleted", "gerald", NewId()));

        var roles = await _sut.ResolveEffectiveUserRoleIdsAsync(NewId(), "xt_deleted_gerald");

        roles.Should().BeEmpty();
        await _mappingStore.DidNotReceive()
            .FindBySourceUserNamesAsync(Arg.Any<IReadOnlyCollection<(string, string)>>());
    }

    private static bool HasIdentity(IReadOnlyCollection<(string, string)> identities, string tenant, string user)
        => identities.Contains((tenant, user));

    private static string NewId() => OctoObjectId.GenerateNewId().ToString();

    private static RtExternalTenantUserMapping Mapping(string tenant, string user, params string[] mappedRoleIds) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        SourceTenantId = tenant,
        SourceUserId = NewId(),
        SourceUserName = user,
        MappedRoleIds = mappedRoleIds.Length == 0 ? null : new AttributeStringValueList(mappedRoleIds.ToList())
    };

    private void ReturnMappings(params RtExternalTenantUserMapping[] mappings)
    {
        _mappingStore.FindBySourceUserNamesAsync(Arg.Any<IReadOnlyCollection<(string, string)>>())
            .Returns(mappings);
    }

    private RtGroup AddGroup(string roleId, params string[] memberIds)
    {
        var group = new RtGroup { RtId = OctoObjectId.GenerateNewId(), GroupName = $"g-{Guid.NewGuid():N}" };
        _groups.Add(group);
        _members[group.RtId] = memberIds.ToList();
        _groupRoles[group.RtId] = [roleId];
        return group;
    }
}
