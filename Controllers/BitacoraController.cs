using Microsoft.AspNetCore.Mvc;

namespace frontendnet;
public class BitacoraController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}