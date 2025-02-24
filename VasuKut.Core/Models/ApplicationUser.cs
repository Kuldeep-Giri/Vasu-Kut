using Microsoft.AspNetCore.Identity;

namespace VasuKut.Core.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Role { get; set; }
    }
}
