using bmerketo.Contexts;
using bmerketo.Helpers.Repositories;
using bmerketo.Models.Dtos;
using bmerketo.Models.Entities;
using bmerketo.Models.ViewModels;

namespace bmerketo.Helpers.Services;

public class ContactService
{
    private readonly IdentityDataContext _context;
    private readonly ContactRepository _repo;

    public ContactService(IdentityDataContext context, ContactRepository repo)
    {
        _context=context;
        _repo=repo;
    }

    public async Task<bool> AddAsync(ContactViewModel viewModel)
    {
        try
        {
            ContactEntity contactEntity = viewModel;
            _context.Contacts.Add(contactEntity);
            await _context.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    public async Task<IEnumerable<Contact>> GetAllContactsAsync()
    {
        var entities = await _repo.GetAllAsync();
        var viewModels = entities.Select(entity => new Contact
        {
            CreatedDate = entity.CreatedDate,
            Name = entity.Name,
            Email = entity.Email,
            PhoneNumber = entity.PhoneNumber,
            CompanyName = entity.Company,
            Message = entity.Message,
           
        }).ToList();

        return viewModels;
    }


}
