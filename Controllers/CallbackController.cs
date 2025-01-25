using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace CustomReverseProxy.Controllers
{
    [ApiController]
    [Route("callback")]
    public class CallbackController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public CallbackController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpGet]
        
        public async Task<IActionResult> Index([FromQuery] string code, [FromQuery] string state)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("Authorization code not found.");
            }

            try
            {
                var tokenResponse = await ExchangeAuthorizationCodeForTokens(code);

                if (tokenResponse == null)
                {
                    return StatusCode(500, "Error exchanging authorization code for tokens.");
                }

                // Decode and process the ID Token if needed
                var idToken = tokenResponse.Id_Token;

                // Process the access token for authorization purposes if needed
                var accessToken = tokenResponse.Access_Token;

                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(idToken);

                Console.WriteLine("Lets check jwtToken value");
                Console.WriteLine(jwtToken);
                var claims = jwtToken.Claims.ToList();

                var claimsIdentity = new ClaimsIdentity(claims, "OIDC");
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                HttpContext.User = claimsPrincipal;

                Console.WriteLine(idToken);
                Console.WriteLine(accessToken);

                // Save tokens to session or cookie
                HttpContext.Session.SetString("id_token", idToken);
                HttpContext.Session.SetString("access_token", accessToken);

                // Redirect to home or any protected resource
                return Redirect("/app1");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Callback processing error: {ex.Message}");
            }
        }

        private async Task<TokenResponse> ExchangeAuthorizationCodeForTokens(string code)
        {
            using var client = new HttpClient();

            var domain = _configuration["Auth0:Domain"];
            var clientId = _configuration["Auth0:ClientId"];
            var clientSecret = _configuration["Auth0:ClientSecret"];
            var redirectUri = _configuration["Auth0:RedirectUri"];
            var Audience = "https://test";
            var tokenEndpoint = $"https://{domain}/oauth/token";

            var requestBody = new
            {
                grant_type = "authorization_code",
                client_id = clientId,
                client_secret = clientSecret,
                code = code,
                redirect_uri = redirectUri,
                audience = Audience
            };

            var requestContent = new StringContent(System.Text.Json.JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

            var response = await client.PostAsync(tokenEndpoint, requestContent);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var responseBody = await response.Content.ReadAsStringAsync();
            /*
            if(responseBody != null)
            {
                HttpContext.Response.ContentType = "text/plain";
                await HttpContext.Response.WriteAsync(responseBody);

                return JsonSerializer.Deserialize<TokenResponse>(responseBody);
            }
            */
            Console.WriteLine(responseBody);
            var formattedResponse = Newtonsoft.Json.JsonConvert.DeserializeObject<TokenResponse>(responseBody);
            if(formattedResponse.Access_Token == null)
            {
                Console.WriteLine("No access token in response");
            }
            Console.WriteLine(formattedResponse.Access_Token);
            Console.WriteLine(formattedResponse.Id_Token);
            Console.WriteLine(formattedResponse.Scope);
            Console.WriteLine(formattedResponse.Expires_In);
            Console.WriteLine(formattedResponse.Token_Type);
            return formattedResponse;
        }
/*
        private ClaimsPrincipal BuildClaimsPrincipal(string tokenResponse)
        {
            // Create ClaimsPrincipal from token response
            // ...
            return new ClaimsPrincipal();
        }
*/
    }

    public class TokenResponse
    {
        public string Access_Token { get; set; }
        public string Id_Token { get; set; }
        public string Scope { get; set; }
        public int Expires_In { get; set; }
        public string Token_Type { get; set; }
    }
}



