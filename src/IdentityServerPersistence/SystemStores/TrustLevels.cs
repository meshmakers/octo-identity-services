using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Helpers over the <see cref="RtTrustLevelEnum" /> trust scale that underpins the two-dimension
///     trust model of the verified external identifier directory (AB#5122).
/// </summary>
/// <remarks>
///     The scale is deliberately a small, totally ordered enum — <c>None &lt; Weak &lt; Strong</c> —
///     so the effective trust of a resolution is a plain minimum over the two dimensions
///     (stored enrollment trust × per-call message trust). The enum's numeric keys carry that order
///     (None=0, Weak=1, Strong=2), so the minimum is over the underlying value.
/// </remarks>
public static class TrustLevels
{
    /// <summary>
    ///     The effective trust rule of the whole directory: <c>effective = min(enrollment, message)</c>.
    ///     A binding is only as trustworthy as its weaker dimension.
    /// </summary>
    public static RtTrustLevelEnum Min(RtTrustLevelEnum enrollmentTrust, RtTrustLevelEnum messageTrust)
        => (int)enrollmentTrust <= (int)messageTrust ? enrollmentTrust : messageTrust;
}
