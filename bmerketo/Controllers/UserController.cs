using bmerketo.Helpers.Services;
using bmerketo.Models.Identities;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace bmerketo.Controllers;
[Authorize(Roles = "admin")]
public class UserController : Controller
{
    private readonly UserManager<CustomIdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AuthService _auth;

    public UserController(UserManager<CustomIdentityUser> userManager, RoleManager<IdentityRole> roleManager, AuthService auth)
    {
        _userManager = userManager;
        _roleManager=roleManager;
        _auth=auth;
    }

    public async Task<IActionResult> Index()
    {
        var viewModel = new UserViewModel
        {
            Users = await _userManager.GetUsersInRoleAsync("user"),
            Admins = await _userManager.GetUsersInRoleAsync("admin")
        };


        return View(viewModel);
    }

    [Route("user/update_{email}")]
    public async Task<IActionResult> Update(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        return View(user);
    }

    [HttpGet]
    [Route("user/update-role_{userId}")]
    public async Task<IActionResult> UpdateRole(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user != null)
        {
            var currentRoles = await _userManager.GetRolesAsync(user);
            var allRoles = await _roleManager.Roles.Select(r => r.Name).ToListAsync();

            var viewModel = new UpdateRoleViewModel
            {
                UserId = userId,
                AvailableRoles = allRoles.Except(currentRoles).ToList()
            };

            return View("UpdateRole", viewModel);
        }

        return RedirectToAction("Error");
    }

    [HttpPost]
    [Route("user/update-role_{userId}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateRole(string userId, string newRole)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user != null)
        {
            var currentRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, currentRoles);
            await _userManager.AddToRoleAsync(user, newRole);

            return RedirectToAction("Index");
        }

        return RedirectToAction("Error");
    }

    public IActionResult NewUser()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> NewUser(AccountRegistrationViewModel model)
    {
        if (ModelState.IsValid)
        {
            if (await _auth.SignUpAsync(model))
            {
                return RedirectToAction("Index", "User");
            }
            else
            {
                ModelState.AddModelError("", "A user with same email already exists");
            }
        }

        return View(model);
    }
}
