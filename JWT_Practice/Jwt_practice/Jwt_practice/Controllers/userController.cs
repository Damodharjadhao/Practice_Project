using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Jwt_practice.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class userController : ControllerBase
    {
        public static user newUser = new user();
        private readonly IConfiguration _configuration;

        public userController(IConfiguration configuration)
        {
            _configuration= configuration;
        }
        
        [HttpPost("Register")]
        public  ActionResult<user> Register(userDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);         

            newUser.userName =request.userName;
            newUser.passwordHash = passwordHash;           
            return Ok(newUser);
        }
             

        [HttpPost("Login")]
        public ActionResult<user> Login(userDto request)
        {
            if(newUser.userName != request.userName)
            {
                return BadRequest("User Not Found");
            }
            if(!BCrypt.Net.BCrypt.Verify(request.Password, newUser.passwordHash))
            {
                return BadRequest("Wrong password");
            }

            var token = createToken(newUser);
            return Ok(token);
        }

      
        private string createToken(user newone)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name , newone.userName),
                 new Claim(ClaimTypes.Role , "Admin")
            };

            var key =new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSetting:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials : creds
                );

            var jwt =new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

      

       
    }
}
