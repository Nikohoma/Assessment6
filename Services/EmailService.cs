using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;

namespace Assessment6AuthService.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config) => _config = config;

        public async Task SendAsync(string to, string subject, string htmlBody)
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(_config["Email:From"]));
            message.To.Add(MailboxAddress.Parse(to));
            message.Subject = subject;
            message.Body = new TextPart(TextFormat.Html) { Text = htmlBody };

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(_config["Email:Host"], int.Parse(_config["Email:Port"]!),
                SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(_config["Email:Username"], _config["Email:Password"]);
            await smtp.SendAsync(message);
            await smtp.DisconnectAsync(true);
        }
    }
}
