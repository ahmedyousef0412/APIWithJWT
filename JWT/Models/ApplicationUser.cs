using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JWT.Models
{

    //This Class to Append Column [firstName , lastName] On Table Built in [IdentityUser]
    public class ApplicationUser  :IdentityUser
    {
        [Required ,MaxLength(50)]
        public string FirstName { get; set; }

        [Required, MaxLength(50)]

        public string LastName { get; set; }
    }
}
