using bmerketo.Helpers.Services;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace bmerketo.Controllers;

[Authorize(Roles = "admin")]
public class ProductsController : Controller
{
    private readonly TagService _tagService;
    private readonly CategoryService _categoryService;
    private readonly ProductService _productService;

    public ProductsController(TagService tagService, CategoryService categoryService, ProductService productService)
    {
        _tagService=tagService;
        _categoryService=categoryService;
        _productService=productService;
    }

    public async Task<IActionResult> Index()
    {
        var product = await _productService.GetAllProductssAsync();
        return View(product);
    }

    public async Task<IActionResult> Add()
    {
        ViewBag.Tags = await _tagService.GetTagsAsync();
        ViewBag.Categories = await _categoryService.GetCategoriesAsync();
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Add(ProductRegistrationViewModel model, string[] tags, string[] categories)
    {
        if (ModelState.IsValid)
        {
            if(await _productService.CreateAsync(model) != null)
            {
                await _productService.AddProductTagsAsync(model, tags);
                await _productService.AddProductCategoriesAsync(model, categories);
                return RedirectToAction("Index");
            }

            ModelState.AddModelError("", "Something went wrong.");
        }

        ViewBag.Tags = await _tagService.GetTagsAsync(tags);
        ViewBag.Categories = await _categoryService.GetCategoriesAsync(categories);
        return View(model);
    }
}
