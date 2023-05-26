using bmerketo.Helpers.Repositories;
using bmerketo.Models.Entities;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace bmerketo.Helpers.Services;

public class CategoryService
{
    private readonly CategoryRepository _repo;

    public CategoryService(CategoryRepository repo)
    {
        _repo=repo;
    }

    public async Task<bool> AddCategoryAsync(CategoryViewModel viewModel)
    {
        await _repo.AddAsync(viewModel);
        return true;
    }

    public async Task<IEnumerable<CategoryViewModel>> GetAllCategoriesAsync()
    {
        var entities = await _repo.GetAllAsync();
        var viewModels = entities.Select(entity => new CategoryViewModel
        {
            Name = entity.CategoryName

        }).ToList();

        return viewModels;
    }

    public async Task<IEnumerable<CategoryViewModel>> GetAllCategoriesAsync(string articlenumber)
    {
        var entities = await _repo.GetAllAsync(x => x.Products.Any(p => p.Product.ArticleNumber == articlenumber));

        var viewModels = entities.Select(entity => new CategoryViewModel
        {
            Name = entity.CategoryName

        }).ToList();

        return viewModels;
    }


    public async Task<List<SelectListItem>> GetCategoriesAsync()
    {
        var categories = new List<SelectListItem>();

        foreach (var category in await _repo.GetAllAsync())
        {
            categories.Add(new SelectListItem
            {
                Value = category.Id.ToString(),
                Text = category.CategoryName,
            });
        }
        return categories;
    }

    public async Task<List<SelectListItem>> GetCategoriesAsync(string[] selectedCategories)
    {
        var categories = new List<SelectListItem>();

        foreach (var category in await _repo.GetAllAsync())
        {
            categories.Add(new SelectListItem
            {
                Value = category.Id.ToString(),
                Text = category.CategoryName,
                Selected = selectedCategories.Contains(category.Id.ToString())
            }); 
        }
        return categories;
    }
}
