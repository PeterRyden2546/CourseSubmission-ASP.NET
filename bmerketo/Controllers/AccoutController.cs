using bmerketo.Helpers.Services;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace bmerketo.Controllers;

public class AccoutController : Controller
{
    private readonly AuthService _auth;

    public AccoutController(AuthService auth)
    {
        _auth=auth;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(AccountRegistrationViewModel model)
    {
        if (ModelState.IsValid)
        {
            if(await _auth.SignUpAsync(model))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "A user with same email already exists");
            }
        }

        return View(model);
    }

    public IActionResult Login(string returnUrl = null!)
    {
        var viewModel = new LoginViewModel();
        if(returnUrl != null) 
            viewModel.ReturnUrl = returnUrl;
        return View(viewModel);
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            if(await _auth.LoginAsync(model))
                return LocalRedirect(model.ReturnUrl);

            ModelState.AddModelError("", "Incorrect e-mail or password");
        }
        return View(model);
    }

    [Authorize]
    public async Task<IActionResult> LogOut()
    {
        if (await _auth.SignOutAsync(User))
            return RedirectToAction("Index", "Home");

        return RedirectToAction("Login", "Accout");
    }
}
