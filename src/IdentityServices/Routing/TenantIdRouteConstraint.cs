namespace Meshmakers.Octo.Backend.IdentityServices.Routing;

/// <summary>
///     Checks if the tenant id is a valid string.
/// </summary>
internal class TenantIdRouteConstraint : IRouteConstraint
{
    public bool Match(HttpContext? httpContext, IRouter? route, string routeKey, RouteValueDictionary values,
        RouteDirection routeDirection)
    {
        // check nulls
        var isMatch = values.TryGetValue(routeKey, out var tenantId) && tenantId != null;
        if (isMatch)
        {
            //  httpContext?.Items.Add(Statics.TenantId, tenantId);
        }

        return isMatch;
    }
}