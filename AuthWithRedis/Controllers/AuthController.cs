using AuthWithRedis.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthWithRedis.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IDistributedCache _cache;

        public AuthController(IDistributedCache cache)
        {
            _cache = cache;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            // Validate the registration
            if (string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password))
            {
                return BadRequest("Username and password are required");
            }

            // Check if the user already exists
            string existingUserId = await _cache.GetStringAsync($"User:{model.Username}");
            if (!string.IsNullOrEmpty(existingUserId))
            {
                return BadRequest("Username already taken");
            }

            // Generate a unique user ID
            string userId = Guid.NewGuid().ToString();

            // Add the user to the cache
            await _cache.SetStringAsync($"User:{model.Username}", userId);

            // Hash the password and add the user's credentials to the cache
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);
            await _cache.SetStringAsync($"User:{userId}:Password", hashedPassword);

            // Create a new session ID
            string sessionId = Guid.NewGuid().ToString();

            // Add the session ID to the cache with a reference to the user ID
            await _cache.SetStringAsync($"Session:{model.Username}", sessionId, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1)
            });

            // Return a JWT token containing the session ID
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("AsbBank_@*2023*@_@*05*@_@*09*@_");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, userId),
                }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(new { Token = tokenHandler.WriteToken(token) });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            // Validate the login data
            if (string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password))
            {
                return BadRequest("Username and password are required");
            }

            // Check if the user exists and get the user ID
            string userId = await _cache.GetStringAsync($"User:{model.Username}");
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid username or password");
            }

            // Check if the password is correct
            string hashedPassword = await _cache.GetStringAsync($"User:{userId}:Password");
            if (!BCrypt.Net.BCrypt.Verify(model.Password, hashedPassword))
            {
                return BadRequest("Invalid username or password");
            }

            // Check if user already has an active session
            var activeSessionId = await _cache.GetStringAsync($"Session:{model.Username}");
            if (activeSessionId == null)
            {
                return Conflict("User session has expired please authenticate again!");
            }

            // Create a new session ID
            string sessionId = Guid.NewGuid().ToString();

            // Add the session ID to the cache with a reference to the user ID
            await _cache.SetStringAsync($"Session:{model.Username}", sessionId, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1)
            });

            //Return a JWT token containing the session ID
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("AsbBank_@*2023*@_@*05*@_@*09*@_");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, userId),
                }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(new { Token = tokenHandler.WriteToken(token) });
        }

        [HttpPost("authenticated")]
        public async Task<IActionResult> Authenticated(LoginModel model)
        {
            // Check if the user already exists
            string existingUserId = await _cache.GetStringAsync($"User:{model.Username}");
            if (string.IsNullOrEmpty(existingUserId))
            {
                return BadRequest("User could not found. Please register first!");
            }

            // Check if the password is correct
            string hashedPassword = await _cache.GetStringAsync($"User:{existingUserId}:Password");
            if (!BCrypt.Net.BCrypt.Verify(model.Password, hashedPassword))
            {
                return BadRequest("Invalid username or password");
            }

            // Create a new session ID
            string sessionId = Guid.NewGuid().ToString();

            // Add the session ID to the cache with a reference to the user ID
            await _cache.SetStringAsync($"Session:{model.Username}", sessionId, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1)
            });

            return Ok($"User is authenticated!");
        }

        private async Task<bool> IsSessionExpired(string sessionId)
        {
            byte[] sessionBytes = await _cache.GetAsync($"Session:{sessionId}");
            if (sessionBytes == null)
            {
                // Session does not exist, so it has expired
                return true;
            }

            // Session is still valid
            return false;
        }
    }
}
