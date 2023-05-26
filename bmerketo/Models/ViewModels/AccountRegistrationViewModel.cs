using bmerketo.Models.Entities;
using bmerketo.Models.Identities;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.ViewModels;

public class AccountRegistrationViewModel
{
    [Display(Name = "Your First Name*")]
    [Required(ErrorMessage = "Your first name is required")]
    [RegularExpression(@"^[a-öA-Ö]{2,}(?:[ é'-][a-öA-Ö]+)*$", ErrorMessage = "you must enter a valid name")]
    public string FirstName { get; set; } = null!;

    [Display(Name = "Your Last Name*")]
    [Required(ErrorMessage = "Your last name is required")]
    [RegularExpression(@"^[a-öA-Ö]{2,}(?:[ é'-][a-öA-Ö]+)*$", ErrorMessage = "you must enter a valid name")]
    public string LastName { get; set; } = null!;

    [Display(Name = "Your Email*")]
    [Required(ErrorMessage = "Your Email is required")]
    [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ErrorMessage = "you must enter a valid e-mail")]
    [DataType(DataType.EmailAddress)]
    public string Email { get; set; } = null!;

    [Display(Name = "Phone Number (optional)")]
    public string? PhoneNumber { get; set; }

    [Display(Name = "Password*")]
    [Required(ErrorMessage = "Password is required")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8,}$", ErrorMessage = "you must enter a valid password")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = null!;

    [Display(Name = "Confirm Password*")]
    [Required(ErrorMessage = "Confirm Password is required")]
    [Compare(nameof(Password), ErrorMessage = "Password and Confirm Password must match")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = null!;

    [Required(ErrorMessage = "Street name is required")]
    [Display(Name = "Street Name*")]
    [RegularExpression(@"^[a-zA-Z0-9\s!@#$%^&*()_+\-=[\]{};':""\\|,.<>\/?]{3,}$")]
    public string StreetName { get; set; } = null!;

    [Required(ErrorMessage = "Postal code is required")]
    [Display(Name = "Postal code*")]
    [DataType(DataType.PostalCode)]
    [RegularExpression(@"^(?=.*\d)\d{3}(?:\s?\d{2})?$")]
    public string PostalCode { get; set; } = null!;

    [Required(ErrorMessage = "City is required")]
    [Display(Name = "City*")]
    [RegularExpression(@"^[\w\d\s!#$%&'*+\-./:;<=>?@[\]^_`{|}~]{2,}$")]
    public string City { get; set; } = null!;

    [Display(Name = "Company Name (optional)")]
    public string? Company { get; set; }


    [Display(Name = "Profile Image (optional)")]
    [DataType(DataType.Upload)]
    public IFormFile? ProfileImage { get; set; }


    public static implicit operator CustomIdentityUser(AccountRegistrationViewModel viewModel)
    {
        return new CustomIdentityUser
        {

            UserName = viewModel.Email,

            FirstName = viewModel.FirstName,
            LastName = viewModel.LastName,
            Email = viewModel.Email,
            PhoneNumber = viewModel.PhoneNumber,

        };

    }

    public static implicit operator ProfileEntity(AccountRegistrationViewModel viewModel)
    {
       var entity = new ProfileEntity
        {
            StreetName = viewModel.StreetName,
            PostalCode = viewModel.PostalCode,
            City = viewModel.City,
            CompanyName = viewModel.Company
        };
        if (viewModel.ProfileImage != null)
            entity.ImageUrl = $"{viewModel.Email}_{viewModel.ProfileImage?.FileName}";
        return entity;
    }
}
