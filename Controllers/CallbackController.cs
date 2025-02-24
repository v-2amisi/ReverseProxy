using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text;
using System.Collections.Generic;
using System.Text.Json;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web;
using System.Xml;

namespace CustomReverseProxy.Controllers
{
    [ApiController]
    [Route("/")]
    public class CallbackController : ControllerBase
    {
        //private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<CallbackController> _logger;
        private readonly IConfiguration _configuration;

        public CallbackController(IConfiguration configuration, ILogger<CallbackController> logger)
        {
            //_httpContextAccessor = httpContextAccessor;
            _logger = logger;
            _configuration = configuration;
        }

        // SAML Callback POST binding
        [HttpPost("saml")]
        public IActionResult HandleSamlPost([FromForm] SamlAuthModel samlResponseModel)
        {
            return ProcessSamlResponse(samlResponseModel);
        }

        // SAML Callback (Redirect Binding)
        [HttpGet("saml")]
        public IActionResult HandleSamlRedirect([FromQuery] string SAMLResponse, [FromQuery] string RelayState)
        {
            var samlModel = new SamlAuthModel
            {
                SamlResponse = SAMLResponse,
                RelayState = RelayState
            };
            return ProcessSamlResponse(samlModel);
        }

        private IActionResult ProcessSamlResponse(SamlAuthModel samlResponseModel)
        {
            if (samlResponseModel == null || string.IsNullOrEmpty(samlResponseModel.SamlResponse))
            {
                Console.WriteLine("SAML Response is null or empty.");
                _logger.LogError("SAML Response is null or empty.");
                return BadRequest("Invalid SAML Response.");
            }

            try
            {
                // Extract claims from SAML response
                ClaimsIdentity identity = samlResponseModel.GetClaimsIdentity();
                var claimsPrincipal = new ClaimsPrincipal(identity);

                // Authenticate user session
                HttpContext.SignInAsync(claimsPrincipal);
                HttpContext.Session.SetString("IsAuthenticated", "true");
                HttpContext.Session.SetString("AuthType", identity.AuthenticationType);
                claimsHtml = "<h1>User Claims</h1><ul>";
                foreach (Claim claim in identity.Claims)
                {
                    claimsHtml += $"<li><strong>{claim.Type}:</strong> {claim.Value}</li>";
                }
                claimsHtml += "</ul>";
                HttpContext.Session.SetString("SAMLClaims", claimsHtml);

                _logger.LogInformation("SAML authentication successful.");
                Console.WriteLine("SAML authentication successful.");

                // Redirect to original requested URL after authentication
                string returnUrl = HttpContext.Session.GetString("returnUrl") ?? "/";
                return Redirect(returnUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing SAML response: {ex.Message}");
                return StatusCode(500, "SAML authentication failed.");
            }
        }

        [HttpGet("callback")]
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
                var claims = jwtToken.Claims;
                
                string allClaims = null;
                foreach (var claim in claims)
                {
                    var claimType = claim.Type;
                    var claimValue = claim.Value;
                    Console.WriteLine(claimType + ":" + claimValue);
                    allClaims += claimType + ":" + claimValue + ";";
                }
                Console.WriteLine("allClaims: " + allClaims);

                HttpContext.Session.SetString("AllIDTokenClaims", allClaims.TrimEnd(';'));


                var claimsIdentity = new ClaimsIdentity(claims, "OIDC");
                
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                

                foreach (var identity in claimsPrincipal.Identities)
                {
                    Console.WriteLine($"CallbackControllerAuthentication Type: {identity.AuthenticationType}");
                    Console.WriteLine($"Is Authenticated: {identity.IsAuthenticated}");
                }

                HttpContext.User = claimsPrincipal;

                // Save tokens to session or cookie
                HttpContext.Session.SetString("id_token", idToken);
                HttpContext.Session.SetString("access_token", accessToken);
                HttpContext.Session.SetString("AuthType", identity.AuthenticationType);
                Console.WriteLine("HttpContext.User.Identity.IsAuthenticated.ToString(): " + HttpContext.User.Identity.IsAuthenticated.ToString());
                HttpContext.Session.SetString("IsAuthenticated", HttpContext.User.Identity.IsAuthenticated.ToString());

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
            
            var formattedResponse = Newtonsoft.Json.JsonConvert.DeserializeObject<TokenResponse>(responseBody);
            if(formattedResponse.Access_Token == null)
            {
                Console.WriteLine("No access token in response");
            }
            return formattedResponse;
        }
    }

    // Models - think about separating model implementations
    public class SamlAuthModel
    {
        public string SamlResponse { get; set; }
        public string RelayState { get; set; }
        //public Dictionary<string, string> Attributes { get; set; } = new Dictionary<string, string>();

        public ClaimsIdentity GetClaimsIdentity()
        {
            //var claims = Attributes.Select(attr => new Claim(attr.Key, attr.Value)).ToList();
            if (string.IsNullOrEmpty(SamlResponse))
            {
                throw new ArgumentNullException(nameof(SamlResponse), "SAMLResponse is null or empty.");
            }

            // Decode the Base64 encoded SAML response
            byte[] decodedBytes = Convert.FromBase64String(SamlResponse);
            string decodedXml = Encoding.UTF8.GetString(decodedBytes);

            // Load the XML document
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(decodedXml);

            // Create a namespace manager for SAML namespaces
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
            nsmgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            nsmgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

            // Select all Attribute nodes in the SAML Assertion
            XmlNodeList attributeNodes = xmlDoc.SelectNodes("//saml:AttributeStatement/saml:Attribute", nsmgr);
            List<Claim> claims = new List<Claim>();

            if (attributeNodes != null)
            {
                foreach (XmlNode attribute in attributeNodes)
                {
                    // Get the Name attribute of the SAML Attribute
                    string attributeName = attribute.Attributes["Name"]?.Value;
                    if (string.IsNullOrEmpty(attributeName))
                    {
                        continue;
                    }

                    // Get the first AttributeValue; you can extend this to handle multiple values if needed.
                    XmlNode attributeValueNode = attribute.SelectSingleNode("saml:AttributeValue", nsmgr);
                    if (attributeValueNode != null)
                    {
                        string attributeValue = attributeValueNode.InnerText;
                        claims.Add(new Claim(attributeName, attributeValue));
                    }
                }
            }
            return new ClaimsIdentity(claims, "SAML");
        }
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



