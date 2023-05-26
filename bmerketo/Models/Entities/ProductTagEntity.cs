using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.Entities;

[PrimaryKey(nameof(ArticleNumber), nameof(TagId))]
public class ProductTagEntity
{
    [StringLength(100)]
    public string ArticleNumber { get; set;} = null!;
    public ProductEntity Product { get; set; } = null!;


    public int TagId { get; set; }
    public TagEntity Tag { get; set; } = null!;
}
