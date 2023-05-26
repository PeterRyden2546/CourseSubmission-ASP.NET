using bmerketo.Models.Entities;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.ViewModels;

public class ContactViewModel
{
    [Display(Name = "Your Name*")]
    [Required(ErrorMessage = "Your name is required")]
    [RegularExpression(@"^[a-öA-Ö]+(?:[ é'-][a-öA-Ö]+)*$", ErrorMessage = "you must enter a valid name")]
    public string Name { get; set; } = null!;

    [Display(Name = "Your Email*")]
    [Required(ErrorMessage = "Your Email is required")]
    [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ErrorMessage = "you must enter a valid e-mail")]
    [DataType(DataType.EmailAddress)]
    public string Email { get; set; } = null!;

    [Display(Name = "Phone Number (optional)")]
    public string? PhoneNumber { get; set; }

    [Display(Name = "Company (optional)")]
    public string? CompanyName { get; set; }

    [Display(Name = "Message*")]
    [Required(ErrorMessage = "Message is required")]
    [RegularExpression(@"^[a-zA-Z0-9\s\n\.\-_,:;!?%()""'<>@,]+", ErrorMessage = "The message contains invalid characters.")]

    public string Message { get; set; } = null!;


    public static implicit operator ContactEntity(ContactViewModel model)
    {
        return new ContactEntity
        {
            Name = model.Name,
            Email = model.Email,
            PhoneNumber = model.PhoneNumber,
            Company = model.CompanyName,
            Message = model.Message,
        };
    }
}
