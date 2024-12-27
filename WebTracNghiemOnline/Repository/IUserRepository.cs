using Microsoft.AspNetCore.Identity;
using WebTracNghiemOnline.Models;

namespace WebTracNghiemOnline.Repository
{
    public interface IUserRepository
    {
        Task<User> FindByEmailandUsernameAsync(string email,string username);
        Task<bool> CreateAsync(User user, string password);
        Task<User> FindByEmaiAsync(string email);
        Task<IdentityResult> AddToRoleAsync(User user, string v);
        Task<bool> CheckPasswordAsync(User user, string password);
        Task<IList<string>> GetRolesAsync(User user);
        Task<User> GetByIdAsync(string userId);
        Task<bool> UpdateAsync(User user);
        Task<User> FindByProviderAsync(string provider, string providerKey);
        Task<bool> CreateAsync(User user); // Không cần mật khẩu
        Task<string> GeneratePasswordResetTokenAsync(User user);
        Task<bool> ResetPasswordAsync(User user, string token, string newPassword);


        /* void UpdateAsync(Task<User> user);*/
    }
}
