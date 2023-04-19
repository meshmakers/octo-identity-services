using System;
using Meshmakers.Common.Shared;

namespace Meshmakers.Octo.Backend.Authentication;

public static class AuthenticationConstants
{
    public const string ExternalLoginRoute = "ExternalLogin";
    public const string ControllerRouteTemplate = ExternalLoginRoute + "/[controller]";

    /// <summary>
    ///     Authentication scheme name used for Bearer
    /// </summary>
    public const string BearerAuthenticationScheme = "Bearer";

    /// <summary>
    ///     Gets OpenID Connect metadata address (Discovery Endpoint).
    ///     https://docs.identityserver.io/en/latest/endpoints/discovery.html
    /// </summary>
    /// <param name="authority"></param>
    /// <returns></returns>
    public static string GetOidcMetadataAddress(string authority)
    {
        return new Uri(authority).Append("/.well-known/openid-configuration").ToString();
    }


    /// <summary>
    ///     Copied from IdentityServer4 Framework. Necessary to prevent necessity of having a reference to IdentityServer4
    ///     nuget package.
    /// </summary>
    public class IdentityServerConstants
    {
        /// <summary>
        ///     The Signout scheme used in IdentityServer
        /// </summary>
        public const string SignoutScheme = "idsrv";

        public const string ExternalCookieAuthenticationScheme = "idsrv.external";
    }
}
