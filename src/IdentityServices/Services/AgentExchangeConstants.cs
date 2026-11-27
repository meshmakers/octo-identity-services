namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Constants of the agent token exchange: an agent's service-account client gets the API scope
///     <see cref="AgentScope" /> instead of <c>octo_api</c>, so its token opens no platform API by itself. Only the MCP
///     service may turn it into a short-lived <c>octo_api</c> token, through the RFC 8693 exchange presented by its
///     confidential client <see cref="ExchangeClientId" /> in the agent's own tenant (<c>TenantExchangeProcessor</c>,
///     <c>TokenEndpointController</c>).
/// </summary>
public static class AgentExchangeConstants
{
    /// <summary>The API scope of an agent's service-account client (System.Identity.Bootstrap, MCP audience only).</summary>
    public const string AgentScope = "octo_agent";

    /// <summary>
    ///     The confidential client of the MCP service that alone may exchange an agent token. MCP registers it in every
    ///     tenant with the secret from its configuration; a client of this id that is public, disabled or has any other
    ///     grant type than the token exchange is refused.
    /// </summary>
    public const string ExchangeClientId = "octo-mcpServices-agent-exchange";

    /// <summary>The one scope an agent exchange issues.</summary>
    public const string IssuedScope = "octo_api";

    /// <summary>The <c>amr</c> value of a token issued by the agent exchange.</summary>
    public const string AuthenticationMethod = "agent_exchange";
}
