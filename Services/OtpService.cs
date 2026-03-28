using Assessment6AuthService.Data;
using Assessment6AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace Assessment6AuthService.Services
{
    public class OtpService
    {
        private readonly AuthDbContext _db;
        private readonly EmailService _emailService;

        public OtpService(AuthDbContext db, EmailService emailService)
        {
            _db = db;
            _emailService = emailService;
        }

        public async Task SendOtpAsync(string email, string purpose)
        {
            // Invalidate old OTPs
            var old = _db.OtpRecords.Where(o => o.Email == email && o.Purpose == purpose && !o.IsUsed);
            _db.OtpRecords.RemoveRange(old);

            var code = new Random().Next(100000, 999999).ToString();

            _db.OtpRecords.Add(new OtpRecord
            {
                Email = email,
                OtpCode = code,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                Purpose = purpose
            });

            await _db.SaveChangesAsync();
            await _emailService.SendAsync(email, "OTP", $"Your OTP is: <b>{code}</b>. Valid for 10 minutes.");
        }

        public async Task<bool> ValidateOtpAsync(string email, string code, string purpose)
        {
            var otp = await _db.OtpRecords
                .Where(o => o.Email == email&& o.OtpCode == code&& o.Purpose == purpose&& !o.IsUsed&& o.ExpiresAt > DateTime.UtcNow).FirstOrDefaultAsync();

            if (otp == null) return false;

            otp.IsUsed = true;
            await _db.SaveChangesAsync();
            return true;
        }
    }
}
