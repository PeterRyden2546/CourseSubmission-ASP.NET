using bmerketo.Helpers.Repositories;
using bmerketo.Models.Entities;
using bmerketo.Models.ViewModels;

namespace bmerketo.Helpers.Services;

public class ProductService
{
    private readonly ProductRepository _productRepo;
    private readonly ProductTagRepository _tagRepo;
    private readonly ProductCategoryRepository _categoryRepo;

    public ProductService(ProductRepository productRepo, ProductTagRepository tagRepo, ProductCategoryRepository categoryRepo)
    {
        _productRepo=productRepo;
        _tagRepo=tagRepo;
        _categoryRepo=categoryRepo;
    }

    public async Task<ProductEntity> CreateAsync(ProductEntity entity)
    {

        var _entity = await _productRepo.GetAsync(x => x.ArticleNumber == entity.ArticleNumber);
        if (_entity == null)
        {
            _entity = await _productRepo.AddAsync(entity);
            if(_entity != null)
                return entity;
        }
        return null!;
    }

    public async Task AddProductTagsAsync(ProductEntity entity, string[] tags)
    {
        foreach (var tag in tags)
        {
            await _tagRepo.AddAsync(new ProductTagEntity
            {
                ArticleNumber = entity.ArticleNumber,
                TagId = int.Parse(tag)
            });
        }
    }

    public async Task AddProductCategoriesAsync(ProductEntity entity, string[] categories)
    {
        foreach (var category in categories)
        {
            await _categoryRepo.AddAsync(new ProductCategoryEntity
            {
                ArticleNumber= entity.ArticleNumber,
                CategoryId = int.Parse(category)
            });
        }
    }

    public async Task<IEnumerable<ProductRegistrationViewModel>> GetAllProductssAsync()
    {
        var entities = await _productRepo.GetAllAsync();
        var viewModels = entities.Select(entity => new ProductRegistrationViewModel
        {
            ArticleNumber = entity.ArticleNumber,
            Name = entity.Name,
            Ingress = entity.Ingress,
            Description = entity.Description,
            Quantity = entity.Quantity,
            Price = entity.Price,
            Tags = entity.Tags.Select(tag => new TagViewModel { Name = tag.Tag.TagName }).ToList(),
            Categories = entity.Categories.Select(category => new  CategoryViewModel { Name = category.Category.CategoryName}).ToList(),
        }).ToList();

        return viewModels;
    }

    public async Task<ProductRegistrationViewModel> GetProductAsync(string articleNumber)
    {
        var product = await _productRepo.GetAsync(x => x.ArticleNumber == articleNumber);
        var entity = new ProductRegistrationViewModel
        {
            ArticleNumber = product.ArticleNumber,
            Name = product.Name,
            Ingress = product.Ingress,
            Description = product.Description,
            Quantity = product.Quantity,
            Price = product.Price,
        };
        
        return entity;
    }

}
