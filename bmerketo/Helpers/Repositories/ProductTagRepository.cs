using bmerketo.Contexts;
using bmerketo.Models.Entities;

namespace bmerketo.Helpers.Repositories
{
    public class ProductTagRepository : Repo<ProductTagEntity>
    {
        public ProductTagRepository(IdentityDataContext dataContext) : base(dataContext)
        {
        }
    }
}
