using bmerketo.Models.Entities;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.ViewModels;

public class TagViewModel
{
    [Display(Name = "Tag Name*")]
    [Required(ErrorMessage = "Category is required")]
    [RegularExpression(@"^[a-öA-Ö]+(?:[ é'-][a-öA-Ö]+)*$", ErrorMessage = "you must enter a valid category")]
    public string Name { get; set; } = null!;

    public static implicit operator TagEntity(TagViewModel model)
    {
        return new TagEntity
        {
            TagName = model.Name,
        };
    }
}
