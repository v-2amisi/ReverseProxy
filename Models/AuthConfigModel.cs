using System.Collections.Generic;

namespace CustomReverseProxy.Models
{
    public class AuthenticationConfig
    {
        public string DefaultAuthSource { get; set; }
        public OidcConfig OIDC { get; set; }
        public SamlConfig SAML { get; set; }
    }

    public class OidcConfig
    {
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string CallbackPath { get; set; }
        public List<string> Scopes { get; set; }
    }

    public class SamlConfig
    {
        public string IdpMetadataUrl { get; set; }
        public string SsoUrl { get; set; }
        public string EntityId { get; set; }
        public string CallbackPath { get; set; }
    }
}
