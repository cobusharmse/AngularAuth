using API.APIModels;
using API.Models;
using Azure.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace API.Controllers
{

    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        private async Task<string> generateToken(AppUser user)
        {
            JwtSecurityTokenHandler JWTtokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.UTF8.GetBytes( _configuration.GetSection("JWTSettings")["SecurityToken"]);
            var roles = await _userManager.GetRolesAsync(user);

            List<Claim> claims =
                [
                    new (JwtRegisteredClaimNames.Email , user.Email??""),
                    new (JwtRegisteredClaimNames.Name , user.FullName??""),
                    new (JwtRegisteredClaimNames.NameId , user.Id??""),
                    new (JwtRegisteredClaimNames.Aud,  _configuration.GetSection("JWTSettings")["ValidAudiance"]),
                    new (JwtRegisteredClaimNames.Iss,  _configuration.GetSection("JWTSettings")["ValidIssuer"])
                ];

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            SecurityTokenDescriptor tokendescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("JWTSettings")["SecurityToken"])), SecurityAlgorithms.HmacSha256),

            };

           JwtSecurityToken token = JWTtokenHandler.CreateJwtSecurityToken(tokendescriptor);
            return JWTtokenHandler.WriteToken(token);
        }

        public AccountController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [Authorize]
        [HttpGet]
        [Route("api/[controller]/currentuser")]
        public async Task<ActionResult<UserDetailsResponseModel>> GetCurrentUser()
        {
            string? currentuserID = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (currentuserID != null)
            { 
             AppUser? user = await _userManager.FindByIdAsync(currentuserID);
                if (user != null)
                {
                    UserDetailsResponseModel returnuser = new UserDetailsResponseModel
                    {
                        Email = user.Email,
                        AccessFailedCount = user.AccessFailedCount,
                        FullName = user.FullName,
                        Id = user.Id,
                        PhoneNumber = user.PhoneNumber,
                        PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                        TwoFactorEnabled = user.TwoFactorEnabled,
                        Roles = [.. await _userManager.GetRolesAsync(user)]
                    };
                    return Ok(returnuser);
                }
                else
                {
                    return Unauthorized();
                }
            }
            else
            {
                return Unauthorized();
            }
        }

        [HttpPost]
        [Route("api/[controller]/token")]
        public async Task<ActionResult<TokenResponseModel>> Token([FromBody] TokenRequestModel request)
        {
            if (ModelState.IsValid)
            {
                try
                {
                   var user =  await _userManager.FindByNameAsync(request.UserName);
                    if (user == null)
                    {
                        return Unauthorized(new TokenResponseModel { IsSuccess = false, Error = "Login failed" });
                    }
                   
                   if(! await _userManager.CheckPasswordAsync(user, request.Password))
                    {
                        return Unauthorized(new TokenResponseModel { IsSuccess = false, Error = "Login failed" });
                    }

                    return Ok(new TokenResponseModel { IsSuccess = true,Token = await generateToken(user) });
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        [HttpPost]
        [Route("api/[controller]/register")]
        public async Task<ActionResult> RegisterAccount([FromBody] RegisterRequestModel request)
        {
            if (ModelState.IsValid)
            {
                try
                {


                    AppUser user = new AppUser
                    {
                        Email = request.Email,
                        FullName = request.FullName,
                        UserName = request.UserName,
                    };

                    var AddResponse = await _userManager.CreateAsync(user, request.Password);
                    if (!AddResponse.Succeeded)
                    {
                        return BadRequest(AddResponse.Errors);
                    }

                    if (request.Roles is null)
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }
                    else
                    {
                        await _userManager.AddToRolesAsync(user, request.Roles);
                    }
                    return Ok();
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}
