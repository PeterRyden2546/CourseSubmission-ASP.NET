namespace bmerketo.Models.ViewModels;

public class UpdateRoleViewModel
{
    public string UserId { get; set; } = null!;
    public List<string> AvailableRoles { get; set; } = null!;
}
