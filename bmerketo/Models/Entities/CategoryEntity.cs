using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.Entities;

public class CategoryEntity
{
    public int Id { get; set; }

    [StringLength(40)]
    public string CategoryName { get; set; } = null!;

    public ICollection<ProductCategoryEntity> Products { get; set; } = new HashSet<ProductCategoryEntity>();
}