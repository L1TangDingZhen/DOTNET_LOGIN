using LOG.DbContext;
using LOG.Models;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace LOG.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {

        private readonly ApplicationDbContext _context;

        public AccountController(ApplicationDbContext context)
        {
            _context = context;
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Models.LoginRequest loginRequest)
        {
            // Register user
            if (string.IsNullOrEmpty(loginRequest.Name) || string.IsNullOrEmpty(loginRequest.Password))
            {
                return BadRequest("Invalid user data");
            }
            
            // enrypt password
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
            // find user
            var user = _context.Users.SingleOrDefault(u => u.Name == loginRequest.Name);

            if (user == null || !PasswordHelper.VerifyPassword(loginRequest.Password, user.Password))
            {
                return Unauthorized("Invalid username or password");
            }

            return Ok("Login successful");
        }
        private bool VerifyPassword(string inputPassword, string storedPassword)
        {
            return inputPassword == storedPassword;
        }

        [HttpPost("cancel")]
        public IActionResult Cancel([FromBody] User user)
        {
            // Cancel user
            if (user == null || string.IsNullOrEmpty(user.Name) || string.IsNullOrEmpty(user.Password))
            {
                return new BadRequestResult();
            }

            var existingUser = _context.Users.SingleOrDefault(u => u.Name == user.Name && u.Password == user.Password);
            if (existingUser == null)
            {
                return NotFound("User not found");
            }

            existingUser.IsActivated = false; // Example upgrade logic
            _context.SaveChanges();

            return new OkResult();
        }

        [HttpPost("uprade")]
        public async Task<IActionResult> TaskAsync<Upgrade>([FromBody] User user)
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
            return Ok("User registered successfully");
        }

        [HttpGet("all")]
        public IActionResult All()
        {
            return Ok(_context.Users.ToList());
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
