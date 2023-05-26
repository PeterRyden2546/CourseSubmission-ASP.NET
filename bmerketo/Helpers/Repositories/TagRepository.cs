using bmerketo.Contexts;
using bmerketo.Models.Entities;

namespace bmerketo.Helpers.Repositories
{
    public class TagRepository : Repo<TagEntity>
    {
        public TagRepository(IdentityDataContext dataContext) : base(dataContext)
        {
        }
    }
}
