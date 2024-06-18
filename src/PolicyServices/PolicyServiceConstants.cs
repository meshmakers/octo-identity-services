namespace Meshmakers.Octo.Backend.PolicyServices;

internal static class PolicyServiceConstants
{
    /// <summary>
    ///     Name of key of database schema
    /// </summary>
    public const string PolicyServiceSchemaVersionKey = "PolicyServices";

    /// <summary>
    ///     Version of database schema for policy service specific data
    /// </summary>
    public const int PolicyServiceSchemaVersionValue = 1;

    public const string PolicyApiReadOnlyPolicy = "PolicyApiReadOnlyPolicy";
    public const string PolicyApiReadWritePolicy = "PolicyApiReadWritePolicy";
}