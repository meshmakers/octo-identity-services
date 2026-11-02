using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Shared.TestUtilities.Builders;

public class RtRoleBuilder
{
    private readonly RtRole _role = new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        Name = "DefaultRole",
        NormalizedName = "DEFAULTROLE"
    };

    public RtRoleBuilder WithRtId(OctoObjectId rtId)
    {
        _role.RtId = rtId;
        return this;
    }

    public RtRoleBuilder WithName(string name)
    {
        _role.Name = name;
        _role.NormalizedName = name.ToUpperInvariant();
        return this;
    }

    public RtRoleBuilder WithClaim(string type, string value)
    {
        _role.Claims ??= new AttributeRecordValueList<RtRoleClaimRecord>();
        _role.Claims.Add(new RtRoleClaimRecord
        {
            ClaimType = type,
            ClaimValue = value
        });
        return this;
    }

    public RtRole Build() => _role;
}
