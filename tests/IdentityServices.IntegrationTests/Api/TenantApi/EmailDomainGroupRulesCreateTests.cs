using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

public class EmailDomainGroupRulesCreateTests : IntegrationTestBase
{
    private const string TenantOwnersGroupRtId = "660000000000000000000040";

    public EmailDomainGroupRulesCreateTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Create_Returns201_WithLocationOfTheStoredRule()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var rule = new EmailDomainGroupRuleDto
        {
            EmailDomainPattern = $"create-{Guid.NewGuid():N}.example",
            TargetGroupRtId = TenantOwnersGroupRtId,
            Description = "created by EmailDomainGroupRulesCreateTests"
        };

        var createResponse = await Client.PostAsJsonAsync(TenantApiUrl("emailDomainGroupRules"), rule, cancellationToken);
        var createBody = await createResponse.Content.ReadAsStringAsync(cancellationToken);

        createResponse.StatusCode.Should().Be(HttpStatusCode.Created, createBody);
        var created = await createResponse.Content.ReadFromJsonAsync<EmailDomainGroupRuleDto>(cancellationToken);
        created!.RtId.Should().NotBeNull();
        created.EmailDomainPattern.Should().Be(rule.EmailDomainPattern);

        var location = createResponse.Headers.Location;
        location.Should().NotBeNull();
        location!.ToString().Should().EndWith($"/emailDomainGroupRules/{created.RtId}");

        var readBack = await Client.GetFromJsonAsync<EmailDomainGroupRuleDto>(location, cancellationToken);
        readBack!.RtId.Should().Be(created.RtId);
        readBack.EmailDomainPattern.Should().Be(rule.EmailDomainPattern);
        readBack.TargetGroupRtId.Should().Be(TenantOwnersGroupRtId);

        await Client.DeleteAsync(TenantApiUrl($"emailDomainGroupRules/{created.RtId}"), cancellationToken);
    }
}
