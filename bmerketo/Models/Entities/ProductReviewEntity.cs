using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace bmerketo.Models.Entities;

public class ProductReviewEntity
{
    public int Id { get; set; }
    public DateTime Created { get; set; } = DateTime.Now;
    public int Rating { get; set; }

    [StringLength(int.MaxValue)]
    public string? Comment { get; set; }

    [ForeignKey(nameof(ArticleNumber))]
    public string ArticleNumber { get; set; } = null!;
    public ProductEntity Product { get; set; } = null!;
}