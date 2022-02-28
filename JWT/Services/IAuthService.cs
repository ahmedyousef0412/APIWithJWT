using JWT.Models;

namespace JWT.Services
{
    public interface IAuthService
    {
        //AuthModel [Type of return]
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);

        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
