namespace API.APIModels
{
    public class TokenResponseModel
    {
        public string? Token { get; set; }
        public bool IsSuccess { get; set; }
        public string? Error { get; set; }
    }
}
