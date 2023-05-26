using bmerketo.Models.Identities;

namespace bmerketo.Models.ViewModels;

public class UserViewModel
{
    public IList<CustomIdentityUser> Users { get; set; } = new List<CustomIdentityUser>();

    public IList<CustomIdentityUser> Admins { get; set; } = new List<CustomIdentityUser>();
}
