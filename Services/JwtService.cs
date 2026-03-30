using Assessment6AuthService.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Assessment6AuthService.Services
{
    public class JwtService
    {
        private readonly IConfiguration _config;

        public JwtService(IConfiguration config) => _config = config;

        public string GenerateToken(User user)
        {
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config["Jwt:Secret"]!));

            var claims = new[]
            {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
        };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(2),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
