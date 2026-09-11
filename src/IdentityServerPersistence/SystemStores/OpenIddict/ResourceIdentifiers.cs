namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     Trailing-slash tolerance for resource indicators (AB#5193).
/// </summary>
/// <remarks>
///     A resource indicator is compared as a string, so <c>https://host/mcp</c> and
///     <c>https://host/mcp/</c> are two different resources — and the two spellings do drift apart
///     in practice: the MCP service advertises its identifier without the slash in its RFC 9728
///     metadata, while <c>System.Identity.Bootstrap</c> seeds the matching API resource with one.
///     Rejecting a login over that difference is never what anyone means, so the lookup treats a
///     trailing slash as insignificant. Nothing else is normalized — host case, port, path and
///     query stay byte-exact, so an unregistered resource is still an unregistered resource.
/// </remarks>
public static class ResourceIdentifiers
{
    /// <summary>Ordinal string equality that ignores trailing slashes.</summary>
    public static IEqualityComparer<string> Comparer { get; } = new TrailingSlashInsensitiveComparer();

    /// <summary>Strips trailing slashes.</summary>
    public static string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.TrimEnd('/');
    }

    /// <summary>
    ///     The spellings to look up for a requested identifier: with and without the trailing
    ///     slash, plus the verbatim value when it matches neither (e.g. a double slash).
    /// </summary>
    public static IEnumerable<string> Variants(string value)
    {
        var normalized = Normalize(value);

        yield return normalized;
        yield return normalized + "/";

        if (!string.Equals(value, normalized, StringComparison.Ordinal) &&
            !string.Equals(value, normalized + "/", StringComparison.Ordinal))
        {
            yield return value;
        }
    }

    private sealed class TrailingSlashInsensitiveComparer : IEqualityComparer<string>
    {
        public bool Equals(string? x, string? y)
            => x is null || y is null
                ? ReferenceEquals(x, y)
                : string.Equals(Normalize(x), Normalize(y), StringComparison.Ordinal);

        public int GetHashCode(string obj) => Normalize(obj).GetHashCode(StringComparison.Ordinal);
    }
}
