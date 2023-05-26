using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace bmerketo.Controllers;

[Authorize(Roles = "admin")]
public class AdminController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
