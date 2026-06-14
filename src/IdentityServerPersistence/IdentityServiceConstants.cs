namespace IdentityServerPersistence;

public static class IdentityServiceConstants
{
    public const string ApiPathPrefix = "{tenantId:tenantId}/v{version:apiVersion}";
    public const string ApiVersion1 = "1.0";

    public const string IdentityApiReadOnlyPolicy = "IdentityApiReadOnlyPolicy";
    public const string IdentityApiReadWritePolicy = "IdentityApiReadWritePolicy";

    public const string MailNotificationConfigurationName = "MailNotificationConfiguration";

    public const string WelcomeEmailTemplateName = "Welcome_Email_Template";
    public const string ResetPasswordEmailTemplateName = "Reset_Password_Email_Template";
    public const string WelcomeEmailWithNoPasswordTemplateName = "Welcome_Email_With_No_Password_Template";

    public const string IdentityMigrationVersionKey = "IdentityServiceMigrations";

    /// <summary>
    /// Phase 3 PR #4: TenantConfiguration row used by <c>PreBlueprintCleanupMigration</c> to hand
    /// captured User → Role and ExternalTenantUserMapping → Role assignments (by role name) over
    /// to the post-blueprint restore step in
    /// <c>DefaultConfigurationCreatorService.SetupTenantAsync</c>. The row is deleted after the
    /// restore completes, so its presence on tenant startup is the gate that runs the restore.
    /// </summary>
    public const string PendingPostBlueprintRoleAssignmentsKey = "PendingPostBlueprintRoleAssignments";
}