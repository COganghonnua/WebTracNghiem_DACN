using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System;
using WebTracNghiemOnline.Models;
using WebTracNghiemOnline.Repository;
using WebTracNghiemOnline.Services;
using Microsoft.AspNetCore.Authentication.Google;

namespace WebTracNghiemOnline.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ExternalAuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserRepository _userRepository;

        public ExternalAuthController(IAuthService authService, IUserRepository userRepository)
        {
            _authService = authService;
            _userRepository = userRepository;
        }

        // Chuyển hướng đến Google
        [HttpGet("signin-google")]
        public IActionResult SignInWithGoogle()
        {
            var redirectUrl = Url.Action("GoogleCallback", "ExternalAuth", null, Request.Scheme);
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        // Xử lý callback từ Google
        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback()
        {
            var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

            if (!result.Succeeded)
            {
                return Unauthorized("Google authentication failed.");
            }

            var claims = result.Principal.Identities.First().Claims;
            var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var providerKey = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(providerKey))
            {
                return BadRequest("Invalid Google response.");
            }

            var user = await _userRepository.FindByEmaiAsync(email);
            if (user == null)
            {
                user = new User
                {
                    UserName = email,
                    Email = email,
                    FullName = name ?? "Google User",
                    Provider = "Google",
                    ProviderKey = providerKey
                };

                var isCreated = await _userRepository.CreateAsync(user);
                if (!isCreated)
                {
                    return BadRequest("Failed to create user.");
                }

                var roleResult = await _userRepository.AddToRoleAsync(user, "User");
                if (!roleResult.Succeeded)
                {
                    return BadRequest("Failed to assign role to user.");
                }
            }

            var token = await _authService.GenerateJwtToken(user);

            // Lưu token vào cookie
            Response.Cookies.Append("jwt", token, new CookieOptions
            {
                HttpOnly = true,        // Ngăn chặn truy cập từ JavaScript
                SameSite = SameSiteMode.None, // Hỗ trợ cross-origin
                Secure = true,          // Yêu cầu HTTPS
                Expires = DateTime.UtcNow.AddMinutes(60) // Hết hạn sau 60 phút
            });

            return Redirect("https://localhost:5173"); 
        }


    }
}
