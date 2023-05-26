using bmerketo.Helpers.Services;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace bmerketo.Controllers;

[Authorize(Roles = "admin")]
public class TagController : Controller
{
    private readonly TagService _tagService;

    public TagController(TagService tagService)
    {
        _tagService=tagService;
    }

    public async Task<IActionResult> Index()
    {
        var tag = await _tagService.GetAllTagsAsync();
        return View(tag);
    }

    public IActionResult Add()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Add(TagViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            if (await _tagService.AddTagAsync(viewModel))
                return RedirectToAction("Index", "Tag");
        }

        ModelState.AddModelError("", "the form was not filled in correctly");

        return View(viewModel);
    }
}
