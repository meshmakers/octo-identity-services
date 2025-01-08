#pragma warning disable 1591
using Asp.Versioning.ApiExplorer;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.PolicyServices.Configuration;
using Meshmakers.Octo.Backend.PolicyServices.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Common;
using Meshmakers.Octo.Services.Swagger.Configuration;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.PolicyServices;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.Configure<OctoPolicyOptions>(options => Configuration.GetSection("Policy").Bind(options));
        services.Configure<OctoSystemConfiguration>(options => Configuration.GetSection("System").Bind(options));


        services.ConfigureOptions<ConfigureDistributionEventHubOptions>();
        services.ConfigureOptions<ConfigureJwtBearerOptions>();

        services.AddTransient<IUserSchemaService, UserSchemaService>();

        services.AddOctoServiceInfrastructure("PolicyService");

        services.AddRuntimeEngine()
            .AddMongoDbRuntimeRepository();

        services.AddAuthentication()
            .AddJwtBearer(jwt => { jwt.Audience = CommonConstants.PolicyApi; });

        services.AddAuthorization(options =>
        {
            options.AddPolicy(PolicyServiceConstants.PolicyApiReadOnlyPolicy, authorizationPolicyBuilder =>
            {
                // require SystemApiFullAccess or SystemApiReadOnly
                authorizationPolicyBuilder.RequireClaim(BackendCommon.ClaimScope, CommonConstants.PolicyApiFullAccess,
                    CommonConstants.PolicyApiReadOnly);
            });

            options.AddPolicy(PolicyServiceConstants.PolicyApiReadWritePolicy, authorizationPolicyBuilder =>
            {
                // require SystemApiFullAccess
                authorizationPolicyBuilder.RequireClaim(BackendCommon.ClaimScope, CommonConstants.PolicyApiFullAccess);
            });
        });

        services.AddOctoApiVersioningAndDocumentation(options =>
        {
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

            options.ApiTitle = "Policy Services API";
            options.ApiDescription = "Octo Mesh Policy Services.";

            options.ClientId = CommonConstants.IdentityServicesSwaggerClientId;
            options.AppName = IdentityTexts.Backend_IdentityServices_UserSchema_Swagger_DisplayName;
        }).AddVersion();

        //  services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
        services.AddControllers();

        services.AddTransient<IConfigureOptions<OctoOpenApiOptions>, ConfigureOctoOpenApiOptions>();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IHost host, IWebHostEnvironment env, ISystemContext systemContext,
        IApiVersionDescriptionProvider apiVersionDescriptionProvider, IUserSchemaService userSchemaService)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseCors();
        app.UseHttpsRedirection();

        app.UseRouting();

        app.UseAuthorization();

        app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
    }
}