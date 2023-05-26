using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.Entities;

[PrimaryKey(nameof(ArticleNumber), nameof(CategoryId))]
public class ProductCategoryEntity
{
    [StringLength(100)]
    public string ArticleNumber { get; set; } = null!;
    public ProductEntity Product { get; set; } = null!;

    public int CategoryId { get; set; }
    public CategoryEntity Category { get; set; } = null!;
}
