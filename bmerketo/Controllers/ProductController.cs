using bmerketo.Helpers.Services;
using Microsoft.AspNetCore.Mvc;

namespace bmerketo.Controllers;

public class ProductController : Controller
{
    private readonly ProductService _productService;
    private readonly CategoryService _categoryService;
    private readonly HomeService _homeService;

    public ProductController(ProductService productService, CategoryService categoryService, HomeService homeService)
    {
        _productService=productService;
        _categoryService=categoryService;
        _homeService=homeService;
    }

    [Route("product/index/{articlenumber}")]
    public async Task<IActionResult> Index(string articlenumber)
    {
        var product = await _productService.GetProductAsync(articlenumber);
        var categories = await _categoryService.GetAllCategoriesAsync(articlenumber);
        var related = await _homeService.GetRelatedAsync();

        ViewBag.Product = product;
        ViewBag.Categories = categories;
        ViewBag.Related = related;

        return View();
    }
}
