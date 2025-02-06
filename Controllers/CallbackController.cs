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
    [Route("/")]
    public class CallbackController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        //private readonly IHttpClientFactory _httpClientFactory;

        public CallbackController(IConfiguration configuration)
        {
            //_httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }
        [HttpGet("callback")]
        
        //public async Task<IActionResult> Index([FromQuery] string code, [FromQuery] string state)
        public async Task<IActionResult> Callback(string code, string state)
        {
            Console.WriteLine("controller is in progress");
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
                var userAccessToken = handler.ReadJwtToken(accessToken);

                //Console.WriteLine("Lets check jwtToken value");
                //Console.WriteLine(jwtToken.Claims);
                //Console.WriteLine(jwtToken.ClaimsIdentity);
                //var claims = jwtToken.Claims.ToList();
                var claims = jwtToken.Claims;
                var allAtClaims = userAccessToken.Claims;
                
                string allClaims = null;
                foreach (var claim in claims)
                {
                    var claimType = claim.Type;
                    var claimValue = claim.Value;
                    Console.WriteLine(claimType + ":" + claimValue);
                    allClaims += claimType + ":" + claimValue + ";";
                    Console.WriteLine("allClaims: " + allClaims);
                    
                    //Console.WriteLine($"Claim Type: {claim.Type}, Claim Value: {claim.Value}");
                    //totalClaims++;
                }

                HttpContext.Session.SetString("AllIDTokenClaims", allClaims.TrimEnd(';'));

                string allAccessClaims = null;
                foreach (var claim in allAtClaims)
                {
                    var claimType = claim.Type;
                    var claimValue = claim.Value;
                    allAccessClaims += claimType + ":" + claimValue + ";";
                }
                
                HttpContext.Session.SetString("AllAccessTokenClaims", allAccessClaims.TrimEnd(';'));

                var claimsIdentity = new ClaimsIdentity(claims, "OIDC");
                
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                

                foreach (var identity in claimsPrincipal.Identities)
                {
                    Console.WriteLine($"CallbackControllerAuthentication Type: {identity.AuthenticationType}");
                    Console.WriteLine($"Is Authenticated: {identity.IsAuthenticated}");
                    //Console.WriteLine($"Name: {identity.name}");
                }

                HttpContext.User = claimsPrincipal;

                //Console.WriteLine(HttpContext.User.Identity.IsAuthenticated);
                //Console.WriteLine(idToken);
                //Console.WriteLine(accessToken);

                // Save tokens to session or cookie
                HttpContext.Session.SetString("id_token", idToken);
                HttpContext.Session.SetString("access_token", accessToken);
                Console.WriteLine("HttpContext.User.Identity.IsAuthenticated.ToString(): " + HttpContext.User.Identity.IsAuthenticated.ToString());
                HttpContext.Session.SetString("IsAuthenticated", HttpContext.User.Identity.IsAuthenticated.ToString());

                // Redirect to home or any protected resource
                return Redirect("/app1");
                //return Redirect("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
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
            //Console.WriteLine(responseBody);
            var formattedResponse = Newtonsoft.Json.JsonConvert.DeserializeObject<TokenResponse>(responseBody);
            if(formattedResponse.Access_Token == null)
            {
                Console.WriteLine("No access token in response");
            }
            //Console.WriteLine(formattedResponse.Access_Token);
            //Console.WriteLine(formattedResponse.Id_Token);
            //Console.WriteLine(formattedResponse.Scope);
            //Console.WriteLine(formattedResponse.Expires_In);
            //Console.WriteLine(formattedResponse.Token_Type);
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



