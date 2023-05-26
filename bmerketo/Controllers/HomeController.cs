using bmerketo.Helpers.Services;
using Microsoft.AspNetCore.Mvc;

namespace bmerketo.Controllers;

public class HomeController : Controller
{
    private readonly HomeService _homeService;
    private readonly CategoryService _categoryService;

    public HomeController(HomeService homeService, CategoryService categoryService)
    {
        _homeService=homeService;
        _categoryService=categoryService;
    }

    public async Task<IActionResult> Index()
    {
        var showCase = await _homeService.GetShowCaseAsync();
        var bestCollection = await _homeService.GetBestCollectionAsync();
        var bestCategories = await _categoryService.GetAllCategoriesAsync();
        var upToSell = await _homeService.GetUpToSellAsync();
        var topSelling = await _homeService.GetTopSellingAsync();

        ViewBag.ShowCase = showCase;
        ViewBag.BestCollection = bestCollection;
        ViewBag.BestCategories = bestCategories;
        ViewBag.UpToSell = upToSell;
        ViewBag.Topselling = topSelling;

        return View();
    }

}
