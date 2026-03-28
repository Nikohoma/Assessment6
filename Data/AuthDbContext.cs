using Assessment6AuthService.Models;
using Microsoft.EntityFrameworkCore;

namespace Assessment6AuthService.Data
{
    public class AuthDbContext:DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<OtpRecord> OtpRecords { get; set; }
    }
}
