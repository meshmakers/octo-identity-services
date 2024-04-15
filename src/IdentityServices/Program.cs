#pragma warning disable 1591
using Duende.IdentityServer.Services;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Consumers;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Routing;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Common;
using Meshmakers.Octo.Services.Common.Authorization;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Meshmakers.Octo.Services.Infrastructure.Middleware;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications;
using Meshmakers.Octo.Services.Swagger.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using NLog;
using NLog.Web;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

// NLog: setup the logger first to catch all errors
var nLogFactory = LogManager.Setup().RegisterNLogWeb().LoadConfigurationFromFile("nlog.config").LogFactory;
var logger = nLogFactory.GetCurrentClassLogger();

try
{
    logger.Debug("init main");

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        Args = args,
        ContentRootPath = Directory.GetCurrentDirectory(),
        WebRootPath = "wwwroot",
    });

    // NLog: Setup NLog for Dependency injection
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(LogLevel.Trace);
    builder.Host.UseNLog();

    // additional providers here needed.
    // allow environment variables to override values from other providers.
    builder.Configuration.AddEnvironmentVariables("OCTO_").AddCommandLine(args)
        .AddUserSecrets(typeof(Program).Assembly, true);


    builder.Services.AddOemServices(builder.Configuration);
    builder.Services.AddScoped<IUserEmailInteractionService, UserEmailInteractionService>();
    builder.Services.AddScoped<IMarkdownRenderService, MarkdownRenderService>();

    builder.Services.Configure<OctoIdentityServicesOptions>(options =>
        builder.Configuration.GetSection("Identity").Bind(options));
    builder.Services.Configure<OctoSystemConfiguration>(options =>
        builder.Configuration.GetSection("System").Bind(options));
    builder.Services.Configure<EmailInteractionConfiguration>(options =>
        builder.Configuration.GetSection("EmailInteraction").Bind(options));
    builder.Services.Configure<RouteOptions>(options =>
        options.ConstraintMap.Add("tenantId", typeof(TenantIdRouteConstraint)));

    builder.Services.Configure<CookiePolicyOptions>(options =>
    {
        // This lambda determines whether user consent for non-essential cookies is needed for a given request.
        options.CheckConsentNeeded = _ => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
    });

    builder.Services.ConfigureOptions<ConfigureDistributionEventHubOptions>();

    builder.Services.AddScoped<INotificationRepository, EntityNotificationRepository>();
    builder.Services.AddScoped<ICorsPolicyService, CorsPolicyService>();
    builder.Services.AddTransient<ICredentialGenerator, CredentialGenerator>();

    builder.Services.AddDynamicAuthentication()
        .AddGoogle()
        .AddFacebook()
        .AddMicrosoft()
        .AddAzureEntraId()
        .AddOpenLdapAuthentication()
        .AddMicrosoftAdAuthentication();

    builder.Services.AddCors();

    builder.Services.AddRuntimeEngine()
        .AddOctoIdentityPersistence(configureDistributionEventHub: c =>
        {
            c.AddBroadcastEventConsumer<IdentityProviderUpdateConsumer, IdentityProviderUpdate>();

            c.AddCommandConsumer<CreateIdentityDataCommandRequestConsumer, CreateIdentityDataCommandRequest>(
                "identity::create-identity-data");
        });

    // Add IdentityServer for authentication using OpenID
    var identityServerBuilder = builder.Services.AddIdentityServer(serverOptions =>
        {
            serverOptions.LicenseKey =
                "eyJhbGciOiJQUzI1NiIsImtpZCI6IklkZW50aXR5U2VydmVyTGljZW5zZWtleS83Y2VhZGJiNzgxMzA0NjllODgwNjg5MTAyNTQxNGYxNiIsInR5cCI6ImxpY2Vuc2Urand0In0.eyJpc3MiOiJodHRwczovL2R1ZW5kZXNvZnR3YXJlLmNvbSIsImF1ZCI6IklkZW50aXR5U2VydmVyIiwiaWF0IjoxNjkzNTA2MjA2LCJleHAiOjE3MjUxMjg2MDYsImNvbXBhbnlfbmFtZSI6ImdlcmFsZC5sb2NobmVyQHNhbHpidXJnZGV2LmF0IiwiY29udGFjdF9pbmZvIjoiZ2VyYWxkLmxvY2huZXJAc2FsemJ1cmdkZXYuYXQiLCJlZGl0aW9uIjoiQ29tbXVuaXR5In0.ekFErBcoKSZ20zgpX0UKoV5vWleMvy8BN6iY7l_30sQyzH_dmsBtVW0G04URgxPgmtMNK7IsQtceyyNhxKr_8ofqiXPArsO2lfm_KXfHfaANUeBFsHfE3H_ajw8U8VjIlBTy3cFkbLUGMDuyDll96xLMlNo03GH9kU7iqMVSzfg5MRmycXppxZ8pCQLwgHxw5TbnGNKol5J7EQIWPiMSfergNdTG_YJpGyjNHdedaWE6rpyRiPDgFTGn4QqVYifD1gpPKkGJnEaIFS5Pv97JOMMv_DEDvZ3U1M4wkJdQJ2PFdND3bEAESWN7LImy66-kXYnsEhPgBRWhpK4FkyFiVg";
            serverOptions.Events.RaiseErrorEvents = true;
            serverOptions.Events.RaiseInformationEvents = true;
            serverOptions.Events.RaiseFailureEvents = true;
            serverOptions.Events.RaiseSuccessEvents = true;
        })
        .AddClientStore<IOctoClientStore>()
        .AddResourceStore<ResourceStore>()
        .AddPersistedGrantStore<PersistentGrantStore>()
        .AddAspNetIdentity<RtUser>()
        .AddProfileService<UserProfileService>()
        .AddCorsPolicyService<CorsPolicyService>()
        .AddAppAuthRedirectUriValidator()
        .AddJwtBearerClientAuthentication();

    // Service that periodically cleans up tokens in grant database
    builder.Services.AddSingleton<IHostedService, TokenCleanupHostService>();

    // Add the extra configuration;
    builder.Services.ConfigureOptions<ConfigureIdentityServerOptions>();
    builder.Services.ConfigureOptions<ConfigureOctoSwaggerOptions>();

    if (builder.Environment.IsDevelopment())
    {
        identityServerBuilder
            .AddDeveloperSigningCredential();
    }
    else
    {
        identityServerBuilder.AddOctoSigningCredential();
    }

    builder.Services.TryAddEnumerable(ServiceDescriptor
        .Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
    builder.Services.ConfigureOptions<ConfigureJwtBearerOptions>();

    builder.Services.AddAuthentication()
        .AddJwtBearer(jwt => { jwt.Audience = CommonConstants.IdentityApi; });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy(IdentityServiceConstants.IdentityApiReadOnlyPolicy, authorizationPolicyBuilder =>
        {
            // require IdentityApiFullAccess or IdentityApiReadOnly
            authorizationPolicyBuilder.RequireClaim(BackendCommon.ClaimScope, CommonConstants.IdentityApiFullAccess,
                CommonConstants.IdentityApiReadOnly);
        });

        options.AddPolicy(IdentityServiceConstants.IdentityApiReadWritePolicy, authorizationPolicyBuilder =>
        {
            // require IdentityApiFullAccess
            authorizationPolicyBuilder.RequireClaim(BackendCommon.ClaimScope,
                CommonConstants.IdentityApiFullAccess);
        });
    });

    builder.Services.AddOctoApiVersioningAndDocumentation(options =>
    {
        options.AddXmlDocAssembly<Program>();
        options.AddXmlDocAssembly<ClientDto>();
        options.Scopes = new Dictionary<string, string>
        {
            {
                CommonConstants.IdentityApiFullAccess,
                IdentityTexts.Backend_IdentityServices_Api_FullAccess
            },
            {
                CommonConstants.IdentityApiReadOnly,
                IdentityTexts.Backend_IdentityServices_Api_ReadOnlyAccess
            }
        };

        options.ApiTitle = "Identity Services API";
        options.ApiDescription = "Octo Mesh Identity Services.";

        options.ClientId = CommonConstants.IdentityServicesSwaggerClientId;
        options.AppName = IdentityTexts.Backend_IdentityServices_UserSchema_Swagger_DisplayName;
    });

    builder.Services.AddAntiforgery(o => o.SuppressXFrameOptionsHeader = true);

    builder.Services.AddMvc();

    builder.Services.AddAutoMapper(typeof(Program));

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
        IdentityModelEventSource.ShowPII = true;
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }

    // Because we are behind an ingress the tls connection is terminated at the ingress itself,
    // the cluster is itself secure and so we reduce complexity by running http, but the discovery
    // documents should always show https.
    app.Use((context, next) =>
    {
        context.Request.Scheme = "https";
        return next();
    });

    app.UseCors();

    // Conversion of request query jwt token to cookie for switch from dashboard to hangfire ui dashboard
    app.UseMiddleware<TenantMiddleware>();
    app.UseMiddleware<CookieBasedAuthorizationMiddleware>();

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseCookiePolicy();

    app.UseOctoApiVersioningAndDocumentation();

    app.UseRouting();

    var supportedCultures = new[] { "en", "de" };
    var localizationOptions = new RequestLocalizationOptions().SetDefaultCulture(supportedCultures[0])
        .AddSupportedCultures(supportedCultures)
        .AddSupportedUICultures(supportedCultures);

    app.UseRequestLocalization(localizationOptions);

    // The sequence of the add statements in the configure function is of importance.
    // app.UseAuthentication()
    // !!!UseIdentityServer calls already UseAuthentication; comes before app.UseMvc();
    app.UseIdentityServer();

    app.UseAuthorization();

    app.MapDefaultControllerRoute();
    app.MapControllerRoute("default", "{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}");

    app.Run();
}
catch (Exception ex)
{
    //NLog: catch setup errors
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    LogManager.Shutdown();
}