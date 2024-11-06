using System.ComponentModel.DataAnnotations;

namespace API.APIModels
{
    public class RegisterRequestModel
    {
        [EmailAddress]
        public required string Email { get; set; } = string.Empty;
        public required string FullName { get; set; } = string.Empty;
        public required string UserName { get; set; } = string.Empty;
        public required string Password { get; set; } = string.Empty;
        public List<string>? Roles { get; set; }
    }
}
