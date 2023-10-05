using Auth.JWT.Simple.Backend.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Auth.JWT.Simple.Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        private Users AuthenticatedUser(Users user)
        {
            Users _user = null;
            if((user.Username == "admin" || user.Username == "aburifat") && user.Password == "123123")
            {
                _user = new Users
                {
                    Username = user.Username
                };
            }
            return _user;
        }

        private string GenerateToken(Users user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));

            var credentials = new SigningCredentials(securitykey,SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, _config["Jwt:Subject"]!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                new Claim("UserName", user.Username)
            };

            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(Users user)
        {
            IActionResult response = Unauthorized();
            var _user = AuthenticatedUser(user);
            if(_user != null )
            {
                var token = GenerateToken(_user);
                response = Ok(new { token = token });
            }

            return response;
        }
    }
}
