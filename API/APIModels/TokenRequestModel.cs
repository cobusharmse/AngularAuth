namespace API.APIModels
{
    public class TokenRequestModel
    {
        public required string UserName { get; set; } = string.Empty;
        public required string Password { get; set; } = string.Empty;

    }
}
