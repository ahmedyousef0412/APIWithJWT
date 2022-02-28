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

        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly JWTMap _jwt;

        public AuthService(UserManager<ApplicationUser> userManager , IOptions<JWTMap> jwt , RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
           _jwt = jwt.Value;
            _roleManager = roleManager;
        }

      

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

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.Email);

            //check on User and Pasword
            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";

                return authModel;
            }


            var jwtSecurityToken = await CreateJwtToken(user);

            var roleList = await _userManager.GetRolesAsync(user);

            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.IsAuthenticated = true;
            authModel.Roles = roleList.ToList();
            authModel.UserName = user.UserName;


            return authModel;

            
        }


        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if(user is null || ! await _roleManager.RoleExistsAsync(model.Role))
            {
                return "Invalid UserId or Role";
            }



            if (await _userManager.IsInRoleAsync(user, model.Role))
            {
                return "User already assign to this Role.";
            }
                

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? String.Empty :"Something went Wrong";
            

                

            
            
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
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: singingCredintials);


            return jwtSecurityToken;
        }
    }
}
