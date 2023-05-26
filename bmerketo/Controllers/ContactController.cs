using bmerketo.Helpers.Services;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace bmerketo.Controllers;

public class ContactController : Controller
{
    private readonly ContactService _contactService;

    public ContactController(ContactService contactService)
    {
        _contactService=contactService;
    }

    public IActionResult Index()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Index(ContactViewModel viewModel)
    {
        if(ModelState.IsValid)
        {
            if(await _contactService.AddAsync(viewModel)) 
                return RedirectToAction("Index", "Home");
        }

        ModelState.AddModelError("", "the form was not filled in correctly");

        return View(viewModel);
    }

    public async Task<IActionResult> ReadContacts()
    {
        var message = await _contactService.GetAllContactsAsync();
        return View(message);
    }
}
