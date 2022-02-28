using JWT.Helper;
using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

using System.Security.Claims;
using System.Text;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace JWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        private readonly JWTMap _jwt;

        public AuthService(UserManager<ApplicationUser> userManager , IOptions<JWTMap> jwt)
        {
            _userManager = userManager;
           _jwt = jwt.Value;
        }

        public IOptions<JWTMap> Jwt { get; }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = "Email is already registered" };
            
            if(await _userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthModel { Message = "UserName is already registered" };

            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

           var result =  await _userManager.CreateAsync(user , model.Password);

            if(!result.Succeeded)
            {
                var error = string.Empty;

                foreach (var errors in result.Errors)
                {
                    error += $"{ errors.Description}, "; 
                }
                return new AuthModel { Message = error };
            }

            await _userManager.AddToRoleAsync(user, Roles.User);


            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { Roles.User },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName,
            };
        }


        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        { 

            var userClaims = await _userManager.GetClaimsAsync(user);

            var roles =  await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));


            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email , user.Email),
                new Claim("uid" ,user.Id)
            }.Union(userClaims).Union(roleClaims);

            var symetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));


            var singingCredintials = new SigningCredentials(symetricSecurityKey ,SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
             
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims, 
                expires : DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: singingCredintials
             );
            return jwtSecurityToken;
        }
    }
}
