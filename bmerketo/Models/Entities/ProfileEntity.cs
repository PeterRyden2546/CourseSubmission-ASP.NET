using bmerketo.Models.Identities;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace bmerketo.Models.Entities
{
    public class ProfileEntity
    {
        [Key, ForeignKey(nameof(User))]
        [StringLength(450)]
        public string Id { get; set; } = null!;

        [Required]
        [StringLength(120)]
        public string StreetName { get; set; } = null!;

        [Required]
        [StringLength(10)]
        public string PostalCode { get; set; } = null!;

        [Required]
        [StringLength(100)]
        public string City { get; set; } = null!;

        [StringLength(100)]
        public string? CompanyName { get; set; }

        [StringLength(int.MaxValue)]
        public string? ImageUrl { get; set; }
        public CustomIdentityUser User { get; set; } = null!;

    }
}
