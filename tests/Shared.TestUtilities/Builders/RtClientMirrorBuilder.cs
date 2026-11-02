using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Shared.TestUtilities.Builders;

public class RtClientMirrorBuilder
{
    private readonly RtClientMirror _mirror = new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        ParentClientId = "default-client",
        ParentTenantId = "octosystem",
        ChildTenantId = "default-child",
        ProvisionedAt = DateTime.UtcNow,
        SecretHashVersion = 0
    };

    public RtClientMirrorBuilder WithRtId(OctoObjectId rtId)
    {
        _mirror.RtId = rtId;
        return this;
    }

    public RtClientMirrorBuilder WithParentClientId(string clientId)
    {
        _mirror.ParentClientId = clientId;
        return this;
    }

    public RtClientMirrorBuilder WithParentTenantId(string tenantId)
    {
        _mirror.ParentTenantId = tenantId;
        return this;
    }

    public RtClientMirrorBuilder WithChildTenantId(string tenantId)
    {
        _mirror.ChildTenantId = tenantId;
        return this;
    }

    public RtClientMirrorBuilder WithProvisionedAt(DateTime provisionedAt)
    {
        _mirror.ProvisionedAt = provisionedAt;
        return this;
    }

    public RtClientMirrorBuilder WithSecretHashVersion(int version)
    {
        _mirror.SecretHashVersion = version;
        return this;
    }

    public RtClientMirror Build() => _mirror;
}
