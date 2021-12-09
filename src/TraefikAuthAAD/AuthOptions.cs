using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace TraefikAuthAAD
{
    public class AuthOptions
    {
        public string Issuer { get; set; } = "c17efc55-82f9-407c-9710-61bb6770bc92";
        public string Audience { get; set; }
        public string Key { get; }

        public AuthOptions(string key, string audience)
        {
            Key = key;
            Audience = audience;
        }

        public SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Key));
        }
    }
}
