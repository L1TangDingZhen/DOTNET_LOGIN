using Microsoft.EntityFrameworkCore;
using LOG.Models;

namespace LOG.DbContext
{
    public class ApplicationDbContext : Microsoft.EntityFrameworkCore.DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // 定义User属性，将User映射到数据库中的Users表, User写到数据库里Users表
        public DbSet<User> Users { get; set; }
    }
}
