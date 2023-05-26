using bmerketo.Models.Entities;
using System.ComponentModel.DataAnnotations;

namespace bmerketo.Models.ViewModels;

public class ProductRegistrationViewModel
{
    [Display(Name = "Article Number")]
    public string ArticleNumber { get; set; } = null!;

    [Display(Name = "Product Name")]
    public string? Name { get; set; }

    [Display(Name = "Ingress")]
    public string? Ingress { get; set; }

    [Display(Name = "Description")]
    public string? Description { get; set; }

    [Display(Name = "Quantity")]
    public int? Quantity { get; set; }

    [Display(Name = "Price")]
    public decimal? Price { get; set; }
    public List<TagViewModel> Tags { get; set; } = new List<TagViewModel>();
    public List<CategoryViewModel> Categories { get; set; } = new List<CategoryViewModel>();

    public static implicit operator ProductEntity(ProductRegistrationViewModel model)
    {
        var entity = new ProductEntity
        {
            ArticleNumber = model.ArticleNumber,
            Name = model.Name,
            Ingress = model.Ingress,
            Description = model.Description,
            Quantity = model.Quantity,
            Price = model.Price,
        };

        if (model.Tags != null)
        {
            foreach (var tag in model.Tags)
            {
                var tagName = new ProductTagEntity
                {
                    ArticleNumber = model.ArticleNumber,
                    Tag = new TagEntity
                    {
                        TagName = tag.Name,
                    }
                };
                entity.Tags.Add(tagName);
            }
        }

        if(model.Categories != null)
        {
            foreach (var category in model.Categories)
            {
                var categoryName = new ProductCategoryEntity
                {
                    ArticleNumber = model.ArticleNumber,
                    Category = new CategoryEntity
                    {
                        CategoryName = category.Name,
                    }
                };
            }
        }

        return entity;
    }
}