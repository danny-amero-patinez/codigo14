using Microsoft.AspNetCore.Mvc;

namespace frontendnet;

public class ArchivosController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

}