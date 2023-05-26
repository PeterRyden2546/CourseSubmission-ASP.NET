using bmerketo.Contexts;
using bmerketo.Models.Entities;

namespace bmerketo.Helpers.Repositories
{
    public class ProductCategoryRepository : Repo<ProductCategoryEntity>
    {
        public ProductCategoryRepository(IdentityDataContext dataContext) : base(dataContext)
        {
        }
    }
}
