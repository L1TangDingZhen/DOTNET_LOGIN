using LOG.DbContext;
using LOG.Models;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using LOG.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace LOG.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly JwtService _jwtService;

        public AccountController(ApplicationDbContext context, JwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Models.LoginRequest loginRequest)
        {
            // Register user
            if (string.IsNullOrEmpty(loginRequest.Name) || string.IsNullOrEmpty(loginRequest.Password))
            {
                return BadRequest("Invalid user data");
            }

            // Encrypt password
            var hashedPassword = PasswordHelper.HashPassword(loginRequest.Password);

            var user = new User
            {
                Name = loginRequest.Name,
                Password = hashedPassword,
                IsActivated = true // 默认激活新用户
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("User registered successfully");
        }

        [HttpPost("login")]
        // there are two LoginRuest classes, one in Models and one in Controllers
        public IActionResult Login([FromBody] Models.LoginRequest loginRequest)
        {
            if (loginRequest == null || string.IsNullOrEmpty(loginRequest.Name) || string.IsNullOrEmpty(loginRequest.Password))
            {
                return BadRequest("Invalid login data");
            }
            // Find user
            var user = _context.Users.SingleOrDefault(u => u.Name == loginRequest.Name);

            if (user == null || !PasswordHelper.VerifyPassword(loginRequest.Password, user.Password))
            {
                return Unauthorized("Invalid username or password");
            }

            var token = _jwtService.GenerateToken(user);
            return Ok(new { Token = "Bearer " + token });
        }

        [Authorize]
        [HttpPost("cancel")]
        public IActionResult Cancel([FromBody] User user)
        {
            // Cancel user
            if (user == null || string.IsNullOrEmpty(user.Name) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("Invalid user data");
            }

            var existingUser = _context.Users.SingleOrDefault(u => u.Name == user.Name && PasswordHelper.VerifyPassword(user.Password, u.Password));
            if (existingUser == null)
            {
                return NotFound("User not found");
            }

            existingUser.IsActivated = false; // Deactivate user
            _context.SaveChanges();

            return Ok("User cancelled successfully");
        }

        [Authorize]
        [HttpPost("upgrade")]
        public async Task<IActionResult> Upgrade([FromBody] User user)
        {
            // Upgrade user
            if (user == null || string.IsNullOrEmpty(user.Name) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("Invalid user data");
            }
            var existingUser = await _context.Users.FindAsync(user.Id);
            if (existingUser == null)
            {
                return NotFound("User not found");
            }

            // Update user
            existingUser.Name = user.Name;
            existingUser.Password = PasswordHelper.HashPassword(user.Password);
            await _context.SaveChangesAsync();

            return Ok("User updated successfully");
        }

        [Authorize]
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            // JWT is stateless, logout can be handled on the client side by removing the token
            return Ok("User logged out successfully");
        }

        [HttpGet("all")]
        public IActionResult All()
        {
            return Ok(_context.Users.ToList());
        }

        //[Authorize]
        //[HttpPost("me")]
        //public IActionResult Me()
        //{
        //    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        //    var user = _context.Users.Find(int.Parse(userId));
        //    if (user == null)
        //    {
        //        return NotFound("User not found");
        //    }

        //    return Ok(new { user.Name });
        //}
        [Authorize]
        [HttpPost("me")]
        public IActionResult Me()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            Console.WriteLine($"User ID from token: {userId}");

            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("User ID claim not found in token");
            }

            var user = _context.Users.Find(int.Parse(userId));
            if (user == null)
            {
                return NotFound($"User not found for ID: {userId}");
            }

            return Ok(new { user.Name });
        }

        [Authorize]
        [HttpPost("refresh")]
        public IActionResult Add(double A, double B)
        {
            var result = A + B;
            return Ok(result);
        }



    }

    public static class PasswordHelper
    {
        public static string HashPassword(string password)
        {
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return $"{Convert.ToBase64String(salt)}.{hashed}";
        }

        public static bool VerifyPassword(string inputPassword, string storedPassword)
        {
            var parts = storedPassword.Split('.');
            var salt = Convert.FromBase64String(parts[0]);
            var hashedPassword = parts[1];

            var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: inputPassword,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return hashed == hashedPassword;
        }
    }
}
