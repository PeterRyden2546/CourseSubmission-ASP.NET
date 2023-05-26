using Microsoft.AspNetCore.Identity;

namespace bmerketo.Helpers.Services;

public class RoleService
{
    private readonly RoleManager<IdentityRole> _roleManager;

    public RoleService(RoleManager<IdentityRole> roleManager)
    {
        _roleManager=roleManager;
    }

    public async Task Roles()
    {
        if(!await _roleManager.RoleExistsAsync("admin"))
            await _roleManager.CreateAsync(new IdentityRole("admin"));

        if (!await _roleManager.RoleExistsAsync("user"))
            await _roleManager.CreateAsync(new IdentityRole("user"));
    }
}
