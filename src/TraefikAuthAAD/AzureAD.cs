namespace TraefikAuthAAD
{
    public class AzureAD
    {
        public string? GroupId { get; set; }
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public string? AuthorizeEndpoint { get; set; }
        public string? TokenEndpoint { get; set; }
    }
}
