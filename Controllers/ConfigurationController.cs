using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using CustomReverseProxy.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CustomReverseProxy.Controllers
{
    [Route("admin/config")]
    public class ConfigurationController : Controller
    {
        private readonly ILogger<ConfigurationController> _logger;
        private readonly IHostEnvironment _hostEnvironment;
        private const string ConfigFileName = "auth-config.json";

        public ConfigurationController(ILogger<ConfigurationController> logger, IHostEnvironment hostEnvironment)
        {
            _logger = logger;
            _hostEnvironment = hostEnvironment;
        }

        // GET: /admin/config
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            try
            {
                string filePath = Path.Combine(_hostEnvironment.ContentRootPath, ConfigFileName);
                if (!System.IO.File.Exists(filePath))
                {
                    return NotFound("Configuration file not found.");
                }

                string json = await System.IO.File.ReadAllTextAsync(filePath);
                var authConfig = JsonSerializer.Deserialize<AuthenticationConfig>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return View(authConfig);
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Error reading configuration file.");
                return StatusCode(500, "Error reading configuration file.");
            }
        }

        // POST: /admin/config
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(AuthenticationConfig authConfig)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", authConfig);
            }

            try
            {
                string filePath = Path.Combine(_hostEnvironment.ContentRootPath, ConfigFileName);
                var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(authConfig, jsonOptions);
                await System.IO.File.WriteAllTextAsync(filePath, json);
                TempData["Message"] = "Configuration updated successfully.";
                return RedirectToAction("Index");
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Error writing configuration file.");
                ModelState.AddModelError("", "Error updating configuration.");
                return View("Index", authConfig);
            }
        }
    }
}
