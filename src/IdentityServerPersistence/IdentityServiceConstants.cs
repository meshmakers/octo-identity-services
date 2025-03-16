namespace IdentityServerPersistence;

public static class IdentityServiceConstants
{
    public const string ApiPathPrefix = "system/v{version:apiVersion}";
    public const string ApiVersion1 = "1.0";

    public const string IdentityApiReadOnlyPolicy = "IdentityApiReadOnlyPolicy";
    public const string IdentityApiReadWritePolicy = "IdentityApiReadWritePolicy";
    public const string IdentitySchemaVersionKey = "IdentityService";
    public const int IdentitySchemaVersionValue = 8;
    
    public const string MailNotificationConfigurationName = "MailNotificationConfiguration";
    
    public const string WelcomeEmailTemplateName = "Welcome_Email_Template";
    public const string ResetPasswordEmailTemplateName = "Reset_Password_Email_Template";
    public const string WelcomeEmailWithNoPasswordTemplateName = "Welcome_Email_With_No_Password_Template";

}