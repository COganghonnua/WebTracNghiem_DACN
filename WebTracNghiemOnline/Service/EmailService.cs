using MailKit.Net.Smtp;
using MimeKit;

namespace WebTracNghiemOnline.Service
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
    }

    public class EmailService : IEmailService
    {
        private readonly string _smtpServer;
        private readonly int _port;
        private readonly string _username;
        private readonly string _password;

        public EmailService(string smtpServer, int port, string username, string password)
        {
            _smtpServer = smtpServer;
            _port = port;
            _username = username;
            _password = password;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var email = new MimeMessage();
            email.From.Add(new MailboxAddress("Web Trắc Nghiệm", _username));
            email.To.Add(MailboxAddress.Parse(toEmail));
            email.Subject = subject;

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = body
            };
            email.Body = bodyBuilder.ToMessageBody();

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(_smtpServer, _port, MailKit.Security.SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(_username, _password);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
        }
    }
}
