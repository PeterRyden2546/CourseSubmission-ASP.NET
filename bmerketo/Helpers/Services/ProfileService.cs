using bmerketo.Helpers.Repositories;
using bmerketo.Models.Entities;
using bmerketo.Models.Identities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace bmerketo.Helpers.Services;

public class ProfileService
{
    private readonly ProfileRepository _repo;
    private readonly UserManager<CustomIdentityUser> _userManager;

    public ProfileService(ProfileRepository repo, UserManager<CustomIdentityUser> userManager)
    {
        _repo=repo;
        _userManager=userManager;
    }

    public async Task<ProfileEntity> GetProfileAsync(string email)
    {
        return await _repo.GetAsync(x => x.User.UserName == email);
    }

    public async Task<CustomIdentityUser> GetUserAsync(string email)
    {
        var user = await _userManager.Users.FirstOrDefaultAsync(x => x.Email == email);
        if (user != null) 
        {
            return user;
        }

        return null!;
    }
}
