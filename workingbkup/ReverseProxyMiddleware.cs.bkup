using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CustomReverseProxy
{
    public class ReverseProxyMiddleware
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly RequestDelegate _nextMiddleware;
        private readonly string _auth0Issuer;
        private readonly string _auth0Audience;

        public ReverseProxyMiddleware(RequestDelegate nextMiddleware)
        {
            _nextMiddleware = nextMiddleware;
            _auth0Issuer = "https://dev-vrk5vwulx3wfsclz.us.auth0.com/";
            _auth0Audience = "https://test";
        }

        public async Task Invoke(HttpContext context)
        {
            var targetUri = BuildTargetUri(context.Request);

            // Check if the request is for the protected resource
            if (targetUri != null && targetUri.Host.StartsWith("ec2-54"))
            {
                // Validate the JWT token
                if (!await IsValidTokenAsync(context.Request))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    Console.WriteLine("Bkup File: Unauthorized: Invalid or missing token.");
                    await context.Response.WriteAsync("Unauthorized: Invalid or missing token.");
                    return;
                }
            }

            if (targetUri != null)
            {
                var targetRequestMessage = CreateTargetMessage(context, targetUri);

                using (var responseMessage = await _httpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    CopyFromTargetResponseHeaders(context, responseMessage);
                    await ProcessResponseContent(context, responseMessage);
                }
                return;
            }
            await _nextMiddleware(context);
        }

        private async Task<bool> IsValidTokenAsync(HttpRequest request)
        {
            // Extract the token from the Authorization header
            if (!request.Headers.TryGetValue("Authorization", out var authorizationHeader))
            {
                return false;
            }

            var token = authorizationHeader.FirstOrDefault()?.Split(" ").Last();
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = _auth0Issuer,
                    ValidateAudience = true,
                    ValidAudience = _auth0Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5),
                    IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                    {
                        // Fetch signing keys from the issuer
                        var client = new HttpClient();
                        var keysJson = client.GetStringAsync($"{_auth0Issuer}.well-known/jwks.json").Result;
                        var signingKeys = new JsonWebKeySet(keysJson).GetSigningKeys();
                        return signingKeys;
                    }
                };

                // Validate the token
                tokenHandler.ValidateToken(token, validationParameters, out _);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private async Task ProcessResponseContent(HttpContext context, HttpResponseMessage responseMessage)
        {
            var content = await responseMessage.Content.ReadAsByteArrayAsync();

            if (IsContentOfType(responseMessage, "text/html") ||
                IsContentOfType(responseMessage, "text/javascript"))
            {
                var stringContent = Encoding.UTF8.GetString(content);
                var newContent = stringContent.Replace("https://www.google.com", "/google")
                    .Replace("https://www.gstatic.com", "/googlestatic")
                    .Replace("https://docs.google.com/forms", "/googleforms");
                await context.Response.WriteAsync(newContent, Encoding.UTF8);
            }
            else
            {
                await context.Response.Body.WriteAsync(content);
            }
        }

        private bool IsContentOfType(HttpResponseMessage responseMessage, string type)
        {
            return responseMessage.Content?.Headers?.ContentType?.MediaType == type;
        }

        private HttpRequestMessage CreateTargetMessage(HttpContext context, Uri targetUri)
        {
            var requestMessage = new HttpRequestMessage();
            CopyFromOriginalRequestContentAndHeaders(context, requestMessage);

            requestMessage.RequestUri = targetUri;
            requestMessage.Headers.Host = targetUri.Host;
            requestMessage.Method = GetMethod(context.Request.Method);

            return requestMessage;
        }

        private void CopyFromOriginalRequestContentAndHeaders(HttpContext context, HttpRequestMessage requestMessage)
        {
            var requestMethod = context.Request.Method;

            if (!HttpMethods.IsGet(requestMethod) &&
                !HttpMethods.IsHead(requestMethod) &&
                !HttpMethods.IsDelete(requestMethod) &&
                !HttpMethods.IsTrace(requestMethod))
            {
                var streamContent = new StreamContent(context.Request.Body);
                requestMessage.Content = streamContent;
            }

            foreach (var header in context.Request.Headers)
            {
                requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
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
            context.Response.Headers.Remove("transfer-encoding");
        }

        private static HttpMethod GetMethod(string method)
        {
            if (HttpMethods.IsDelete(method)) return HttpMethod.Delete;
            if (HttpMethods.IsGet(method)) return HttpMethod.Get;
            if (HttpMethods.IsHead(method)) return HttpMethod.Head;
            if (HttpMethods.IsOptions(method)) return HttpMethod.Options;
            if (HttpMethods.IsPost(method)) return HttpMethod.Post;
            if (HttpMethods.IsPut(method)) return HttpMethod.Put;
            if (HttpMethods.IsTrace(method)) return HttpMethod.Trace;
            return new HttpMethod(method);
        }

        private Uri BuildTargetUri(HttpRequest request)
        {
            Uri targetUri = null;
            PathString remainingPath;

            if (request.Path.StartsWithSegments("/googleforms", out remainingPath))
            {
                targetUri = new Uri("https://docs.google.com/forms" + remainingPath);
            }

            if (request.Path.StartsWithSegments("/app1", out remainingPath))
            {
                targetUri = new Uri("https://ec2-54-82-60-31.compute-1.amazonaws.com:5001");
            }

            return targetUri;
        }
    }
}

