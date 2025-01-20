namespace IdentityServerPersistence;

public static class IdentityServiceConstants
{
    public const string ApiPathPrefix = "system/v{version:apiVersion}";
    public const string ApiVersion1 = "1.0";

    public const string IdentityApiReadOnlyPolicy = "IdentityApiReadOnlyPolicy";
    public const string IdentityApiReadWritePolicy = "IdentityApiReadWritePolicy";
    public const string IdentitySchemaVersionKey = "IdentityService";
    public const int IdentitySchemaVersionValue = 5;
}