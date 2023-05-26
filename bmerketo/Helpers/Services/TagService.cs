using bmerketo.Helpers.Repositories;
using bmerketo.Models.ViewModels;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace bmerketo.Helpers.Services;

public class TagService
{
    private readonly TagRepository _repo;

    public TagService(TagRepository repo)
    {
        _repo=repo;
    }

    public async Task<bool> AddTagAsync(TagViewModel viewModel)
    {
        await _repo.AddAsync(viewModel);
        return true;
    }

    public async Task<IEnumerable<TagViewModel>> GetAllTagsAsync()
    {
        var entities = await _repo.GetAllAsync();
        var viewModels = entities.Select(entity => new TagViewModel
        {
            Name = entity.TagName

        }).ToList();

        return viewModels;
    }

    public async Task<List<SelectListItem>> GetTagsAsync()
    {
        var tags = new List<SelectListItem>();

        foreach(var tag in await _repo.GetAllAsync())
        {
            tags.Add(new SelectListItem
            {
                Value = tag.Id.ToString(),
                Text = tag.TagName,
            });
        }
        return tags;
    }

    public async Task<List<SelectListItem>> GetTagsAsync(string[] selectedTags)
    {
        var tags = new List<SelectListItem>();

        foreach (var tag in await _repo.GetAllAsync())
        {
            tags.Add(new SelectListItem
            {
                Value = tag.Id.ToString(),
                Text = tag.TagName,
                Selected = selectedTags.Contains(tag.Id.ToString())
            });
        }
        return tags;
    }
}
