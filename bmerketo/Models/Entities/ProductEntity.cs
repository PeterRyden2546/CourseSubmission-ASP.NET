using bmerketo.Models.ViewModels;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace bmerketo.Models.Entities;

public class ProductEntity
{
    [Key]
    [StringLength(100)]
    public string ArticleNumber { get; set; } = null!;

    [StringLength(100)]
    public string? Name { get; set; }

    [StringLength(250)]
    public string? Ingress { get; set; }

    [StringLength(int.MaxValue)]
    public string? Description { get; set; }
    public int? Quantity { get; set; }

    [Column(TypeName = "money")]
    public decimal? Price { get; set; }

    public ICollection<ProductTagEntity> Tags { get; set; } = new HashSet<ProductTagEntity>();
    public ICollection<ProductReviewEntity> Reviews { get; set; } = new HashSet<ProductReviewEntity>();
    public ICollection<ProductCategoryEntity> Categories { get; set; } = new HashSet<ProductCategoryEntity>();


}
