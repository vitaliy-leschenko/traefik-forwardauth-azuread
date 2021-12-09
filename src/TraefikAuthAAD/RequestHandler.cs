using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Web;

namespace TraefikAuthAAD
{
    public class RequestHandler
    {
        private readonly string cookieName = "traefik-auth";
        private readonly HttpContext context;
        private readonly AzureAD options;

        private readonly string proto;
        private readonly string host;
        private readonly string forwardedUri;
        private readonly string targetSite;
        private readonly string callback;
        private readonly AuthOptions authOptions;

        public RequestHandler(IHttpContextAccessor httpContextAccessor, IOptions<AzureAD> options, IConfiguration configuration)
        {
            context = httpContextAccessor.HttpContext ?? throw new InvalidOperationException("Can't get http context");
            this.options = options.Value;

            proto = context.Request.Headers["X-Forwarded-Proto"];
            host = context.Request.Headers["X-Forwarded-Host"];
            forwardedUri = context.Request.Headers["X-Forwarded-Uri"];

            targetSite = proto + "://" + host;

            callback = targetSite + "/.well-known/callback";
            authOptions = new AuthOptions(configuration["JwtSigningKey"], targetSite);
        }

        public async Task HandleAsync()
        {
            if (context.Request.Cookies.TryGetValue(cookieName, out var token) && ValidateToken(token))
            {
                await Ok();
            }
            else
            {
                var handled = false;
                if (!string.IsNullOrEmpty(forwardedUri) && forwardedUri.ToLower().StartsWith("/.well-known/callback"))
                {
                    var jwt = await CreateAuthTokenAsync();
                    if (!string.IsNullOrEmpty(jwt))
                    {
                        await AuthorizeWebSiteAsync(jwt);
                        handled = true;
                    }
                }

                if (!handled)
                {
                    await RedirectToAuthorizeServerAsync();
                }
            }
        }

        private async Task AuthorizeWebSiteAsync(string jwt)
        {
            context.Response.Cookies.Append(cookieName, jwt);
            context.Response.Redirect(targetSite);
            await context.Response.WriteAsync("KO");
        }

        private async Task<string?> CreateAuthTokenAsync()
        {
            var uri = new Uri(proto + "://" + host + forwardedUri);
            var code = HttpUtility.ParseQueryString(uri.Query).Get("code");
            if (!string.IsNullOrEmpty(code))
            {
                var json = await GetAccessToken(code);
                if (json != null)
                {
                    var accessToken = json.Value<string>("access_token");
                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        var groups = await GetGroupsAsync(accessToken);

                        if (string.IsNullOrEmpty(options.GroupId) || groups.Contains(options.GroupId))
                        {
                            var handler = new JwtSecurityTokenHandler();
                            var jwt = (JwtSecurityToken)handler.ReadToken(json.Value<string>("id_token"));

                            var oid = jwt.Claims.FirstOrDefault(t => t.Type == "oid")?.Value ?? string.Empty;
                            var name = jwt.Claims.FirstOrDefault(t => t.Type == "name")?.Value ?? string.Empty;
                            var email = jwt.Claims.FirstOrDefault(t => t.Type == "preferred_username")?.Value ?? string.Empty;

                            var now = DateTime.UtcNow;
                            var claims = new List<Claim> 
                            {
                                new Claim(ClaimTypes.NameIdentifier, oid),
                                new Claim(ClaimTypes.Name, name),
                                new Claim(ClaimTypes.Email, email)
                            };
                            var signingCredentials = new SigningCredentials(
                                authOptions.GetSymmetricSecurityKey(), 
                                SecurityAlgorithms.HmacSha256);
                            jwt = new JwtSecurityToken(
                                issuer: authOptions.Issuer,
                                audience: authOptions.Audience,
                                notBefore: now,
                                expires: now.AddYears(10),
                                claims: claims,
                                signingCredentials: signingCredentials);
                            return handler.WriteToken(jwt);
                        }
                    }
                }
            }
            return null;
        }

        private async Task<IList<string>> GetGroupsAsync(string accessToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me/memberOf");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var client = new HttpClient();
            using var response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var json = JsonConvert.DeserializeObject<JObject>(responseContent);
                if (json != null && json["value"] is JArray list)
                {
                    return list.Select(x => x.Value<string>("id") ?? string.Empty)
                        .Where(s => !string.IsNullOrEmpty(s))
                        .ToList();
                }
            }
            return Array.Empty<string>();
        }

        private async Task<JObject?> GetAccessToken(string code)
        {
            var tokenUri = options.TokenEndpoint;
            var form = new Dictionary<string, string?>
            {
                ["client_id"] = options.ClientId,
                ["client_secret"] = options.ClientSecret,
                ["scope"] = "openid profile User.Read",
                ["redirect_uri"] = callback,
                ["code"] = code,
                ["grant_type"] = "authorization_code"
            };

            using var client = new HttpClient();
            var content = new FormUrlEncodedContent(form);
            using var httpRepsponse = await client.PostAsync(tokenUri, content);
            var responseContent = await httpRepsponse.Content.ReadAsStringAsync();
            var json = JsonConvert.DeserializeObject<JObject>(responseContent);
            if (json == null)
            {
                return null;
            }
            return json.TryGetValue("error_description", out JToken? error) && error != null ? null : json;
        }

        private bool ValidateToken(string? token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = authOptions.GetSymmetricSecurityKey(),
                    ValidAudience = authOptions.Audience,
                    ValidIssuer = authOptions.Issuer
                }, out var validated);

                return validated != null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private async Task RedirectToAuthorizeServerAsync()
        {
            var authorizeEndpoint = $"{options.AuthorizeEndpoint}?client_id={options.ClientId}&response_type=code&scope=openid+profile+User.Read&redirect_uri={HttpUtility.UrlEncode(callback)}";
            context.Response.Redirect(authorizeEndpoint);
            await context.Response.WriteAsync("KO");
        }

        private async Task Ok()
        {
            context.Response.StatusCode = 200;
            await context.Response.WriteAsync("OK");
        }
    }
}
