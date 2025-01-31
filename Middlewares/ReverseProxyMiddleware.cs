using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace CustomReverseProxy.Middlewares
{
    public class ReverseProxyMiddleware
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly RequestDelegate _next;
        //private readonly string _oidcCallbackPath = "/callback";

        public ReverseProxyMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            if (!context.Session.IsAvailable)
            {
                await _next(context);
                return;
            }
            
            string requestedUrl = context.Request.Path;

            // Step 1: Determine if authentication is needed
            if (IsProtectedRoute(requestedUrl) && !context.User.Identity.IsAuthenticated){
                //string returnUrl = context.Request.Path + context.Request.QueryString;
                string returnUrl = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5001";
                context.Session.SetString("returnUrl", returnUrl);
                
                // Redirect user to Authentication Middleware (/auth/login)
                context.Response.Redirect($"/auth/login?redirect_uri={returnUrl}");
                return;
            }

            await _next(context);
        }

        private bool IsProtectedRoute(string url)
        {
            return url.StartsWith("/app1");
        }
    /*

        public async Task Invoke(HttpContext context)
        {
            Console.WriteLine("Calling build target uri");
            Console.WriteLine(context.User.Identity.IsAuthenticated);
            var targetUri = BuildTargetUri(context);

            if (targetUri != null)
            {
                Console.WriteLine($"Calling build target message: {context.User.Identity.IsAuthenticated}");
                var targetRequestMessage = CreateTargetMessage(context, targetUri);

                using (var responseMessage = await _httpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    Console.WriteLine($"Calling copy from target resp headers: {context.User.Identity.IsAuthenticated}");
                    CopyFromTargetResponseHeaders(context, responseMessage);
                    await responseMessage.Content.CopyToAsync(context.Response.Body);
                }
                return;
            }

            await _next(context);
        }
/*
        private async Task HandleOidcCallbackAsync(HttpContext context)
        {
            // Process the OIDC callback request
            var code = context.Request.Query["code"];
            var state = context.Request.Query["state"];

            if (string.IsNullOrEmpty(code))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Authorization code is missing");
                return;
            }

            // Log the state and authorization code for debugging (remove in production)
            Console.WriteLine($"Authorization Code: {code}");
            Console.WriteLine($"State: {state}");

            // Exchange the authorization code for tokens
            var tokenResponse = await ExchangeCodeForTokensAsync(code);

            if (tokenResponse != null)
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync($"Access Token: {tokenResponse.AccessToken}\nID Token: {tokenResponse.IdToken}");
            }
            else
            {
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Failed to exchange code for tokens");
            }
        }
*/
/*
        private async Task<TokenResponse> ExchangeCodeForTokensAsync(string code)
        {
            var tokenEndpoint = "https://dev-vrk5vwulx3wfsclz.us.auth0.com/oauth/token"; // Replace with your Auth0 token endpoint
            var clientId = "Nov7Lx4Ggg3mCh2AGsvmaabV7LV40uvv";
            var clientSecret = "MmHqNp-KGvSg5VSu7mmq4hsYieJ2Idgi_8eig0jKAvfNp4bjVaGV1KbryJiqujVX";
            var redirectUri = "https://ec2-54-82-60-31.compute-1.amazonaws.com:5443/callback";

            var requestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
            });

            var response = await _httpClient.PostAsync(tokenEndpoint, requestContent);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                return System.Text.Json.JsonSerializer.Deserialize<TokenResponse>(jsonResponse);
            }

            return null;
        }
*/
/*
        private HttpRequestMessage CreateTargetMessage(HttpContext context, Uri targetUri)
        {
            var requestMessage = new HttpRequestMessage
            {
                RequestUri = targetUri,
                Method = new HttpMethod(context.Request.Method)
            };

            // Copy headers from the original request
            foreach (var header in context.Request.Headers)
            {
                if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                {
                    requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }
            Console.WriteLine($"Target message built: {context.User.Identity.IsAuthenticated}");
            return requestMessage;
        }

        private Uri BuildTargetUri(HttpContext context)
        {
            // Configure routing to backend applications
            
            if (context.Request.Path.StartsWithSegments("/app1"))
            {
                Console.WriteLine("TargetUri: https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
                Console.WriteLine(context.User.Identity.IsAuthenticated);
                return new Uri("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
            }
            if (context.Request.Path.StartsWithSegments("/app2"))
            {
                return new Uri("http://ec2-54-82-60-31.compute-1.amazonaws.com:5000");
            }

            return null;
        }

        private void CopyFromTargetResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
        {
            foreach (var header in responseMessage.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }

            foreach (var header in responseMessage.Content.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            Console.WriteLine($"copied target response headers: {context.User.Identity.IsAuthenticated}");
            context.Response.Headers.Remove("transfer-encoding");
        }
    }
*/
/*
    public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string IdToken { get; set; }
    }
*/
    }
}

