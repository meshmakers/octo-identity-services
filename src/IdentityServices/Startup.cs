using Duende.IdentityServer.Services;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
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
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Meshmakers.Octo.Services.Infrastructure.Middleware;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications;
using Meshmakers.Octo.Services.Swagger.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices;

/// <summary>
///     The startup class
/// </summary>
public class Startup
{
    private readonly IWebHostEnvironment _webHostEnvironment;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="webHostEnvironment"></param>
    /// <param name="configuration"></param>
    public Startup(IWebHostEnvironment webHostEnvironment, IConfiguration configuration)
    {
        _webHostEnvironment = webHostEnvironment;
        Configuration = configuration;
    }

    private IConfiguration Configuration { get; }

    /// <summary>
    ///     This method gets called by the runtime. Use this method to add services to the container.
    /// </summary>
    /// <param name="services"></param>
    public void ConfigureServices(IServiceCollection services)
    {
        services.Configure<CookiePolicyOptions>(options =>
        {
            // This lambda determines whether user consent for non-essential cookies is needed for a given request.
            options.CheckConsentNeeded = _ => true;
            options.MinimumSameSitePolicy = SameSiteMode.None;
        });


        services.AddOemServices(Configuration);
        services.AddScoped<IUserEmailInteractionService, UserEmailInteractionService>();
        services.AddScoped<IMarkdownRenderService, MarkdownRenderService>();

        services.Configure<OctoIdentityServicesOptions>(options =>
            Configuration.GetSection("Identity").Bind(options));
        services.Configure<OctoSystemConfiguration>(options =>
            Configuration.GetSection("System").Bind(options));
        services.Configure<EmailInteractionConfiguration>(options =>
            Configuration.GetSection("EmailInteraction").Bind(options));
        services.Configure<RouteOptions>(options =>
            options.ConstraintMap.Add("tenantId", typeof(TenantIdRouteConstraint)));
        services.Configure<IISOptions>(iis =>
        {
            iis.AuthenticationDisplayName = "Windows";
            iis.AutomaticAuthentication = false;
        });

        services.ConfigureOptions<ConfigureDistributionEventHubOptions>();

        services.AddScoped<INotificationRepository, EntityNotificationRepository>();
        services.AddScoped<ICorsPolicyService, CorsPolicyService>();
        services.AddTransient<ICredentialGenerator, CredentialGenerator>();

        services.AddDynamicAuthentication()
            .AddGoogle()
            .AddMicrosoft()
            .AddOpenIdConnect()
            .AddOpenLdapAuthentication()
            .AddMicrosoftAdAuthentication();

        services.AddCors();

        services.AddRuntimeEngine()
            .AddOctoIdentityPersistence(configureDistributionEventHub: c =>
            {
                c.AddCommandConsumer<CreateIdentityDataCommandRequestConsumer, CreateIdentityDataCommandRequest>(
                    "identity::create-identity-data");
            });

        services.AddInitializationService<DefaultConfigurationInitializationService>();

        // Add IdentityServer 4 for authentication using OpenID
        var identityServerBuilder = services.AddIdentityServer(serverOptions =>
            {
                serverOptions.LicenseKey =
                    "***REMOVED-DUENDE-LICENSE-AB3837***";
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
        services.AddSingleton<IHostedService, TokenCleanupHostService>();

        // Add the extra configuration;
        services.ConfigureOptions<ConfigureIdentityServerOptions>();
        services.ConfigureOptions<ConfigureOctoSwaggerOptions>();

        if (_webHostEnvironment.IsDevelopment())
        {
            identityServerBuilder
                .AddDeveloperSigningCredential();
        }
        else
        {
            identityServerBuilder.AddOctoSigningCredential();
        }

        services.TryAddEnumerable(ServiceDescriptor
            .Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
        services.ConfigureOptions<ConfigureJwtBearerOptions>();

        services.AddAuthentication()
            .AddJwtBearer(jwt => { jwt.Audience = CommonConstants.IdentityApi; });

        services.AddAuthorization(options =>
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

        services.AddOctoApiVersioningAndDocumentation(options =>
        {
            options.AddXmlDocAssembly<Startup>();
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

        services.AddAntiforgery(o => o.SuppressXFrameOptionsHeader = true);

        services.AddMvc();

        services.AddAutoMapper(typeof(Startup));
    }

    /// <summary>
    ///     This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    /// </summary>
    /// <param name="app"></param>
    // ReSharper disable once UnusedMember.Global
    public void Configure(IApplicationBuilder app)
    {
        if (_webHostEnvironment.IsDevelopment())
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

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapDefaultControllerRoute();
            endpoints.MapControllerRoute("default",
                "{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}");
        });
    }
}