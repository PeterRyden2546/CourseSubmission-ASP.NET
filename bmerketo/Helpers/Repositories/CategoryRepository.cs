using bmerketo.Contexts;
using bmerketo.Models.Entities;

namespace bmerketo.Helpers.Repositories;

public class CategoryRepository : Repo<CategoryEntity>
{
    public CategoryRepository(IdentityDataContext dataContext) : base(dataContext)
    {
    }
}
