using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.Entities;

public class TagEntity
{
    public int Id { get; set; }

    [StringLength(40)]
    public string TagName { get; set; } = null!;

    public ICollection<ProductTagEntity> Products { get; set; } = new HashSet<ProductTagEntity>();
}
