using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WebTracNghiemOnline.DTO;
using WebTracNghiemOnline.Repository;
using WebTracNghiemOnline.Service;
using WebTracNghiemOnline.Services;

namespace WebTracNghiemOnline.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserRepository _userRepository;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthController(IAuthService authService, IUserRepository userRepository, IEmailService emailService, IConfiguration configuration)
        {
            _authService = authService;
            _userRepository = userRepository;
            _emailService = emailService;
            _configuration = configuration;
        }
        

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterUserDto model)
        {
            var result = await _authService.RegisterAsync(model);
            if (result == "User registered successfully.")
                return Ok(new { message = result });

            return BadRequest(new { message = result });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginUserDto model)
        {
            var token = await _authService.LoginAsync(model);
            if (token == null)
                return Unauthorized(new { message = "Email hoặc mật khẩu không đúng." });

            // Gửi token qua cookie
            Response.Cookies.Append("jwt", token, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None, // Nếu chạy localhost:5173 và localhost:7253
                Secure = true, // Sử dụng HTTPS
                Expires = DateTime.UtcNow.AddMinutes(60)
            });

            return Ok(new { token }); // Trả token trong response body (nếu cần test qua header)
        }

        /* [HttpGet("me")]
         public async Task<IActionResult> GetCurrentUser()
         {
             try
             {
                 // Lấy token từ cookie
                 var token = Request.Cookies["jwt"];
                 Console.WriteLine(token);
                 if (string.IsNullOrEmpty(token))
                     return Unauthorized(new { message = "Không tìm thấy token. Vui lòng đăng nhập lại." });

                 // Giải mã token
                 var handler = new JwtSecurityTokenHandler();
                 var jwtToken = handler.ReadJwtToken(token);

                 // Kiểm tra Issuer và Audience
                 if (jwtToken.Issuer != "Dung" || !jwtToken.Audiences.Contains("client"))
                     return Unauthorized(new { message = "Token không hợp lệ. Vui lòng đăng nhập lại." });

                 foreach (var claim in jwtToken.Claims)
                 {
                     Console.WriteLine($"Type: {claim.Type}, Value: {claim.Value}");
                 }

                 // Lấy UserId từ Claim (nameid)
                 var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == "nameid")?.Value;
                 if (string.IsNullOrEmpty(userId))
                     return Unauthorized(new { message = "Token không hợp lệ." });

                 // Tìm thông tin người dùng từ database
                 var user = await _authService.GetUserByIdAsync(userId);
                 if (user == null)
                     return Unauthorized(new { message = "Không tìm thấy người dùng. Vui lòng đăng nhập lại." });

                 // Trả về thông tin người dùng
                 return Ok(new
                 {
                     email = user.Email,
                     fullName = user.FullName,
                     balance = user.Balance
                 });
             }
             catch (Exception ex)
             {
                 Console.WriteLine("Lỗi khi xử lý token: " + ex.Message);
                 return StatusCode(500, new { message = "Có lỗi xảy ra.", details = ex.Message });
             }
         }*/

        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            try
            {
                var token = Request.Cookies["jwt"];
                if (string.IsNullOrEmpty(token))
                    return Unauthorized(new { message = "Không tìm thấy token. Vui lòng đăng nhập lại." });

                var user = await _authService.ValidateTokenAsync(token);
                var roles = await _userRepository.GetRolesAsync(user);

                return Ok(new
                {
                    email = user.Email,
                    fullName = user.FullName,
                    balance = user.Balance,
                    roles // Trả về vai trò
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Có lỗi xảy ra.", details = ex.Message });
            }
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Append("jwt", "", new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                Secure = true,
                Expires = DateTime.UtcNow.AddDays(-1) // Xóa cookie
            });
            return Ok(new { message = "Logged out successfully." });
        }


        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto model)
        {
            if (string.IsNullOrEmpty(model.Email))
                return BadRequest(new { message = "Email không được để trống." });

            var user = await _userRepository.FindByEmaiAsync(model.Email);
            if (user == null)
                return NotFound(new { message = "Không tìm thấy người dùng với email này." });

            var token = await _authService.GeneratePasswordResetTokenAsync(user);
            Console.WriteLine("---------token: ",token);
            // Lấy URL frontend từ cấu hình
            var frontendUrl = _configuration["FrontendUrl"];
            Console.WriteLine(frontendUrl);
            var resetUrl = $"{frontendUrl}/reset-password?token={token}&email={model.Email}";
            var emailBody = $"<p>Chào {user.FullName},</p>" +
                            $"<p>Vui lòng nhấn vào liên kết dưới đây để đặt lại mật khẩu của bạn:</p>" +
                            $"<a href=\"{resetUrl}\">{resetUrl}</a>";

            await _emailService.SendEmailAsync(user.Email, "Đặt lại mật khẩu", emailBody);

            return Ok(new { message = "Email đặt lại mật khẩu đã được gửi." });
        }


        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto model)
        {
            if (string.IsNullOrEmpty(model.Email) || string.IsNullOrEmpty(model.Token) || string.IsNullOrEmpty(model.NewPassword))
            {
                Console.WriteLine($"Dữ liệu thiếu: Email={model.Email}, Token={model.Token}, NewPassword={(string.IsNullOrEmpty(model.NewPassword) ? "EMPTY" : "PROVIDED")}");
                return BadRequest(new { message = "Thông tin không đầy đủ." });
            }

            try
            {
                Console.WriteLine($"Reset password cho Email: {model.Email}, Token: {model.Token}");
                var result = await _authService.ResetPasswordAsync(model.Email, model.Token, model.NewPassword);

                if (!result)
                {
                    Console.WriteLine("Reset password thất bại. Token không hợp lệ hoặc đã hết hạn.");
                    return BadRequest(new { message = "Đặt lại mật khẩu thất bại. Token có thể đã hết hạn hoặc không hợp lệ." });
                }

                Console.WriteLine("Reset password thành công.");
                return Ok(new { message = "Đặt lại mật khẩu thành công." });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Lỗi khi đặt lại mật khẩu: {ex.Message}");
                return StatusCode(500, new { message = "Có lỗi xảy ra.", details = ex.Message });
            }
        }



    }
}
