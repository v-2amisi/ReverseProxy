namespace CustomReverseProxy.Models
{
    public class AppSettings
    {
        public string Domain { get; set; }
        public string ClientId { get; set; }
	    public string RedirectUri {get; set;}
        public string ClientSecret {get; set;}
    }
}

