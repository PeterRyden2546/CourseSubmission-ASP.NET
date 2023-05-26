using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.Identities
{
    public class CustomIdentityUser : IdentityUser
    {
        [ProtectedPersonalData]
        [StringLength(70)]
        public string FirstName { get; set; } = null!;


        [ProtectedPersonalData]
        [StringLength(70)]
        public string LastName { get; set; } = null!;


    }
}
