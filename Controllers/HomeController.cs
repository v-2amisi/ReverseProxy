using Microsoft.AspNetCore.Mvc;

namespace CustomReverseProxy.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet("/")]
        public IActionResult Index()
        {
            return Ok("Welcome to the Reverse Proxy App!");
        }
    }
}

