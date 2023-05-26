using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.Entities;

public class ContactEntity
{
    [Key]
    public int Id { get; set; }
    public DateTime CreatedDate { get; set; } = DateTime.Now;

    [StringLength(50)]
    public string Name { get; set; } = null!;

    [Column(TypeName = "varchar(70)")]
    public string Email { get; set; } = null!;

    [Column(TypeName = "char(13)")]
    public string? PhoneNumber { get; set; }

    [StringLength(70)]
    public string? Company { get; set; }

    [StringLength(int.MaxValue)]
    public string Message { get; set; } = null!;

}

