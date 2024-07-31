using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LOG.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [Column(TypeName = "varchar(255)")]
        public string Name { get; set; } = string.Empty;

        [Required]
        [Column(TypeName = "varchar(255)")]
        public string Password { get; set; } = string.Empty;

        public bool IsActivated { get; set; } = true;
    }

    public class LoginRequest
    {
        [Required]
        [Column(TypeName = "varchar(255)")]
        public string Name { get; set; } = string.Empty;

        [Required]
        [Column(TypeName = "varchar(255)")]
        public string Password { get; set; } = string.Empty;
    }
}
