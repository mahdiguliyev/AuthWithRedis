using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace AuthWithRedis.Handler
{
    public class SessionAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IDistributedCache _cache;

        public SessionAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IDistributedCache cache) : base(options, logger, encoder, clock)
        {
            _cache = cache;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string sessionId = Request.Headers["ASB-Session-Id"].ToString();

            if (string.IsNullOrEmpty(sessionId))
            {
                return AuthenticateResult.Fail("Missing session ID");
            }

            string userId = await _cache.GetStringAsync($"Session:{sessionId}");
            if (string.IsNullOrEmpty(userId))
            {
                return AuthenticateResult.Fail("Invalid session ID");
            }

            var identity = new ClaimsIdentity(new[]
            {
            new Claim(ClaimTypes.Name, userId)
        }, Scheme.Name);

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}
