using bmerketo.Contexts;
using bmerketo.Models.Entities;
using bmerketo.Models.Identities;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;


namespace bmerketo.Helpers.Services;

public class AuthService
{
    private readonly UserManager<CustomIdentityUser> _userManager;
    private readonly SignInManager<CustomIdentityUser> _signInManager;
    private readonly IdentityDataContext _context;
    private readonly RoleService _roleService;

    public AuthService(UserManager<CustomIdentityUser> userManager, SignInManager<CustomIdentityUser> signInManager, IdentityDataContext context, RoleService roleService)
    {
        _userManager=userManager;
        _signInManager=signInManager;
        _context=context;
        _roleService=roleService;
    }

    public async Task<bool> SignUpAsync(AccountRegistrationViewModel model)
    {
        try
        {
            await _roleService.Roles();

            var roleName = "user";
            if (!await _userManager.Users.AnyAsync())
                roleName = "admin";

            CustomIdentityUser identityUser = model;
            await _userManager.CreateAsync(identityUser, model.Password);

            await _userManager.AddToRoleAsync(identityUser, roleName);

            ProfileEntity profileEntity = model;
            profileEntity.Id = identityUser.Id;

            _context.Profiles.Add(profileEntity);
            await _context.SaveChangesAsync();

            return true;
        }
        catch { return false; }
    }


    public async Task<bool> LoginAsync(LoginViewModel model)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(x => x.Email == model.Email);

        if (user != null)
        {
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, false);
            return result.Succeeded;
        }
        return false;
    }

    public async Task<bool> SignOutAsync(ClaimsPrincipal user)
    {
        await _signInManager.SignOutAsync();
        return _signInManager.IsSignedIn(user);

    }

}
