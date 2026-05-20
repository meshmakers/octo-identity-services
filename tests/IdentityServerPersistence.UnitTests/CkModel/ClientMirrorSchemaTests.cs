using FluentAssertions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.CkModel;

/// <summary>
/// Schema-level checks for the Phase 1 multi-tenant client credentials additions:
/// the new <c>AutoProvisionInChildTenants</c> attribute on <c>RtClient</c> and the
/// new <c>RtClientMirror</c> CK type. Locking these down keeps a CK-model regression
/// (e.g. a YAML rename that defaults a different value) from silently breaking the
/// auto-provisioning flow.
/// </summary>
public class ClientMirrorSchemaTests
{
    [Fact]
    public void NewClient_AutoProvisionInChildTenants_DefaultsToFalse()
    {
        // The CK attribute is declared with `defaultValues: [false]`, which is the
        // safe default — every client that pre-dates this feature must keep the
        // existing "single-tenant" behaviour.
        var client = new RtClientBuilder().Build();

        client.AutoProvisionInChildTenants.Should().BeFalse();
    }

    [Fact]
    public void Client_CanSetAutoProvisionInChildTenants()
    {
        var client = new RtClientBuilder()
            .WithAutoProvisionInChildTenants()
            .Build();

        client.AutoProvisionInChildTenants.Should().BeTrue();
    }

    [Fact]
    public void RtClientMirror_HoldsAllRequiredAttributes()
    {
        var provisionedAt = new DateTime(2026, 5, 20, 14, 0, 0, DateTimeKind.Utc);
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithParentTenantId("octosystem")
            .WithChildTenantId("acme")
            .WithProvisionedAt(provisionedAt)
            .WithSecretHashVersion(3)
            .Build();

        mirror.ParentClientId.Should().Be("ci-deploy");
        mirror.ParentTenantId.Should().Be("octosystem");
        mirror.ChildTenantId.Should().Be("acme");
        mirror.ProvisionedAt.Should().Be(provisionedAt);
        mirror.SecretHashVersion.Should().Be(3);
    }

    [Fact]
    public void NewClientMirror_SecretHashVersion_DefaultsToZero()
    {
        // The CK attribute is declared with `defaultValues: [0]`. A fresh mirror
        // starts at version 0; the parent tenant's secret-rotation consumer bumps
        // it on every rotation, so out-of-date mirrors can be detected.
        var mirror = new RtClientMirror();

        mirror.SecretHashVersion.Should().Be(0);
    }
}
