using Assessment6AuthService.Data;
using Assessment6AuthService.Models;
using Assessment6AuthService.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Assessment6AuthService.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly AuthDbContext _db;
        private readonly JwtService _jwt;
        private readonly OtpService _otp;

        public AuthController(AuthDbContext db, JwtService jwt, OtpService otp)
        {
            _db = db; _jwt = jwt; _otp = otp;
        }

        // 1. Register — send OTP
        [HttpPost("register/send-otp")]
        public async Task<IActionResult> RegisterSendOtp([FromBody] EmailDto dto)
        {
            if (await _db.Users.AnyAsync(u => u.Email == dto.Email))
                return Conflict("Email already registered.");

            await _otp.SendOtpAsync(dto.Email, "register");
            return Ok("OTP sent to your email.");
        }

        // 2. Register — verify OTP + set password
        [HttpPost("register/verify")]
        public async Task<IActionResult> RegisterVerify([FromBody] RegisterDto dto)
        {
            if (!await _otp.ValidateOtpAsync(dto.Email, dto.Otp, "register"))
                return BadRequest("Invalid or expired OTP.");

            var user = new User
            {
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                IsEmailVerified = true
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { token = _jwt.GenerateToken(user) });
        }

        // 3. Login with password
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return Unauthorized("Invalid credentials.");

            if (!user.IsEmailVerified)
                return Unauthorized("Email not verified.");

            return Ok(new { token = _jwt.GenerateToken(user) });
        }

        // Passwordless login via OTP
        [HttpPost("login/send-otp")]
        public async Task<IActionResult> LoginSendOtp([FromBody] EmailDto dto)
        {
            if (!await _db.Users.AnyAsync(u => u.Email == dto.Email))
                return NotFound("User not found.");

            await _otp.SendOtpAsync(dto.Email, "login");
            return Ok("OTP sent.");
        }

        [HttpPost("login/verify-otp")]
        public async Task<IActionResult> LoginVerifyOtp([FromBody] OtpLoginDto dto)
        {
            if (!await _otp.ValidateOtpAsync(dto.Email, dto.Otp, "login"))
                return BadRequest("Invalid or expired OTP.");

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            return Ok(new { token = _jwt.GenerateToken(user!) });
        }
    }

    public record EmailDto(string Email);
    public record RegisterDto(string Email, string Otp, string Password);
    public record LoginDto(string Email, string Password);
    public record OtpLoginDto(string Email, string Otp);
}
