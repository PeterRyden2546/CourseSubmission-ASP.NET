using bmerketo.Helpers.Repositories;
using bmerketo.Models.ViewModels;

namespace bmerketo.Helpers.Services;

public class HomeService
{
    private readonly ProductRepository _repo;

    public HomeService(ProductRepository repo)
    {
        _repo=repo;
    }

    public async Task<ProductRegistrationViewModel> GetShowCaseAsync()
    {
        var showCase = "SHOW CASE";
        var showProducts = await _repo.GetAllAsync(x => x.Tags.Any(t => t.Tag.TagName == showCase));
        var showProduct = showProducts.FirstOrDefault();

        var productView = new ProductRegistrationViewModel
        {
            ArticleNumber = showProduct!.ArticleNumber,
            Name = showProduct.Name,
            Ingress = showProduct.Ingress,
            Description = showProduct.Description,
            Quantity = showProduct.Quantity,
            Price = showProduct.Price
        };

        return productView;
    }

    public async Task<List<ProductRegistrationViewModel>> GetBestCollectionAsync()
    {
        var bestCollectionTag = "Best Collection";
        var bestCollectionProducts = await _repo.GetAllAsync(x => x.Tags.Any(t => t.Tag.TagName == bestCollectionTag));

        var productViews = bestCollectionProducts.Select(showProduct => new ProductRegistrationViewModel
        {
            ArticleNumber = showProduct.ArticleNumber,
            Name = showProduct.Name,
            Ingress = showProduct.Ingress,
            Description = showProduct.Description,
            Quantity = showProduct.Quantity,
            Price = showProduct.Price,
        }).ToList();

        return productViews;
    }

    public async Task<List<ProductRegistrationViewModel>> GetUpToSellAsync()
    {
        var upToSell = "UP TO SELL";
        var bestCollectionProducts = await _repo.GetAllAsync(x => x.Tags.Any(t => t.Tag.TagName == upToSell));

        var productViews = bestCollectionProducts.Select(showProduct => new ProductRegistrationViewModel
        {
            ArticleNumber = showProduct.ArticleNumber,
            Name = showProduct.Name,
            Ingress = showProduct.Ingress,
            Description = showProduct.Description,
            Quantity = showProduct.Quantity,
            Price = showProduct.Price,
        }).ToList();

        var firstTwoProducts = productViews.Take(2).ToList();

        return firstTwoProducts;
    }

    public async Task<List<ProductRegistrationViewModel>> GetTopSellingAsync()
    {
        var topSellingTag = "Top selling products in this week";
        var topSellingProducts = await _repo.GetAllAsync(x => x.Tags.Any(t => t.Tag.TagName == topSellingTag));

        var productViews = topSellingProducts.Select(showProduct => new ProductRegistrationViewModel
        {
            ArticleNumber = showProduct.ArticleNumber,
            Name = showProduct.Name,
            Ingress = showProduct.Ingress,
            Description = showProduct.Description,
            Quantity = showProduct.Quantity,
            Price = showProduct.Price,
        }).ToList();

        return productViews;
    }

    public async Task<List<ProductRegistrationViewModel>> GetRelatedAsync()
    {
        var relatedTag = "Related Products";
        var bestCollectionProducts = await _repo.GetAllAsync(x => x.Tags.Any(t => t.Tag.TagName == relatedTag));

        var productViews = bestCollectionProducts.Select(showProduct => new ProductRegistrationViewModel
        {
            ArticleNumber = showProduct.ArticleNumber,
            Name = showProduct.Name,
            Ingress = showProduct.Ingress,
            Description = showProduct.Description,
            Quantity = showProduct.Quantity,
            Price = showProduct.Price,
        }).ToList();

        return productViews;
    }
}
