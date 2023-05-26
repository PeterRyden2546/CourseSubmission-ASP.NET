using bmerketo.Models.Entities;

namespace bmerketo.Models.Dtos;

public class Contact
{
    public DateTime CreatedDate { get; set; }
    public string Name { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string? PhoneNumber { get; set; }
    public string? CompanyName { get; set; }
    public string Message { get; set; } = null!;


    public static implicit operator ContactEntity(Contact model)
    {
        return new ContactEntity
        {
            CreatedDate = model.CreatedDate,
            Name = model.Name,
            Email = model.Email,
            PhoneNumber = model.PhoneNumber,
            Company = model.CompanyName,
            Message = model.Message,
        };
    }
}
