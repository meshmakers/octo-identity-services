namespace IdentityServerPersistence;

public static class IdentityServiceConstants
{
    public const string ApiPathPrefix = "{tenantId:tenantId}/v{version:apiVersion}";
    public const string ApiVersion1 = "1.0";

    public const string IdentityApiReadOnlyPolicy = "IdentityApiReadOnlyPolicy";
    public const string IdentityApiReadWritePolicy = "IdentityApiReadWritePolicy";

    // AB#5859: scope AND tenant role. Users, roles, groups, mappings, data permissions → UserManagement.
    public const string IdentityUserAdministrationReadPolicy = "IdentityUserAdministrationReadPolicy";
    public const string IdentityUserAdministrationWritePolicy = "IdentityUserAdministrationWritePolicy";

    // AB#5859: clients, client mirrors, API resources/scopes/secrets, identity providers, e-mail domain
    // group rules, cross-tenant admin provisioning → TenantManagement or UserManagement.
    public const string IdentityTenantAdministrationReadPolicy = "IdentityTenantAdministrationReadPolicy";
    public const string IdentityTenantAdministrationWritePolicy = "IdentityTenantAdministrationWritePolicy";

    // AB#5859: read-only directory lookups that operational UIs need (role names, a client's roles and
    // actors) → UserManagement, TenantManagement, AdminPanelManagement or CommunicationManagement.
    public const string IdentityDirectoryReadPolicy = "IdentityDirectoryReadPolicy";

    // AB#5859: service-wide operations (log level) → TenantManagement in the system tenant only.
    public const string IdentityServiceAdministrationPolicy = "IdentityServiceAdministrationPolicy";

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