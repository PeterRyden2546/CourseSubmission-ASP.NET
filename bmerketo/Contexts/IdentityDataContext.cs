using bmerketo.Models.Entities;
using bmerketo.Models.Identities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace bmerketo.Contexts;

public class IdentityDataContext : IdentityDbContext<CustomIdentityUser>
{
    public IdentityDataContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<ProfileEntity> Profiles { get; set; }
    public DbSet<ContactEntity> Contacts { get; set; }
    public DbSet<ProductEntity> Products { get; set; }
    public DbSet<TagEntity> Tags { get; set; }
    public DbSet<ProductTagEntity> ProductTags { get; set; }
    public DbSet<ProductReviewEntity> ProductReviews { get; set; }
    public DbSet<CategoryEntity> Categories { get; set; }
    public DbSet<ProductCategoryEntity> ProductCategories { get; set; }
}
