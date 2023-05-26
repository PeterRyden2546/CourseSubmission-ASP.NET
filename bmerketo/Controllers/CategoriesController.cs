using bmerketo.Helpers.Services;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace bmerketo.Controllers;

[Authorize(Roles = "admin")]
public class CategoriesController : Controller
{
    private readonly CategoryService _categoryService;

    public CategoriesController(CategoryService categoryService)
    {
        _categoryService=categoryService;
    }

    public async Task<IActionResult> Index()
    {
        var category = await _categoryService.GetAllCategoriesAsync();
        return View(category);
    }


    public IActionResult Add()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Add(CategoryViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            if (await _categoryService.AddCategoryAsync(viewModel))
                return RedirectToAction("Index", "Categories");
        }

        ModelState.AddModelError("", "the form was not filled in correctly");

        return View(viewModel);
    }
}
