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
///     trailing slash as insignificant — the trailing slash of the PATH, that is: a slash inside a
///     query or fragment is part of the value. Nothing else is normalized — host case, port, path
///     segments and query stay byte-exact, so an unregistered resource is still an unregistered
///     resource.
/// </remarks>
public static class ResourceIdentifiers
{
    /// <summary>Ordinal string equality that ignores trailing slashes.</summary>
    public static IEqualityComparer<string> Comparer { get; } = new TrailingSlashInsensitiveComparer();

    /// <summary>Strips trailing slashes from the path, leaving any query or fragment untouched.</summary>
    public static string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var (path, suffix) = SplitPath(value);
        return path.TrimEnd('/') + suffix;
    }

    /// <summary>
    ///     The spellings to look up for a requested identifier: with and without the trailing
    ///     path slash, plus the verbatim value when it matches neither (e.g. a double slash).
    /// </summary>
    public static IEnumerable<string> Variants(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var (path, suffix) = SplitPath(value);
        var trimmed = path.TrimEnd('/');

        var withoutSlash = trimmed + suffix;
        var withSlash = trimmed + "/" + suffix;

        yield return withoutSlash;
        yield return withSlash;

        if (!string.Equals(value, withoutSlash, StringComparison.Ordinal) &&
            !string.Equals(value, withSlash, StringComparison.Ordinal))
        {
            yield return value;
        }
    }

    /// <summary>
    ///     Splits at the first <c>?</c> or <c>#</c>. Purely lexical on purpose: parsing into a
    ///     <see cref="Uri" /> and reassembling would also lower-case the host, drop a default
    ///     port and decode escapes — all differences that must stay significant here.
    /// </summary>
    private static (string Path, string Suffix) SplitPath(string value)
    {
        var cut = value.AsSpan().IndexOfAny('?', '#');
        return cut < 0
            ? (value, string.Empty)
            : (value[..cut], value[cut..]);
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
