namespace Assessment6AuthService.Models
{
    public class OtpRecord
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string OtpCode { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; } = false;
        public string Purpose { get; set; } = string.Empty; // "register" | "login"
    }
}
