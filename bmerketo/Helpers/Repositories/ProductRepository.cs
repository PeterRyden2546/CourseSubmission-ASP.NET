using bmerketo.Contexts;
using bmerketo.Models.Entities;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace bmerketo.Helpers.Repositories
{
    public class ProductRepository : Repo<ProductEntity>
    {
        public ProductRepository(IdentityDataContext dataContext) : base(dataContext)
        {
        }

        public override async Task<IEnumerable<ProductEntity>> GetAllAsync(Expression<Func<ProductEntity, bool>> predicate)
        {
            try
            {
                var query = _dataContext.Set<ProductEntity>()
                    .Include(p => p.Tags)
                    .ThenInclude(x => x.Tag)
                    .Include(z => z.Categories)
                    .ThenInclude(c => c.Category)
                    .Where(predicate);

                var items = await query.ToListAsync();
                return items!;
            }
            catch
            {
                return null!;
            }
        }

        public override async Task<IEnumerable<ProductEntity>> GetAllAsync()
        {
            try
            {
                var query = _dataContext.Set<ProductEntity>()
                    .Include(p => p.Tags)
                    .ThenInclude(x => x.Tag)
                    .Include(z => z.Categories)
                    .ThenInclude(c => c.Category);

                var items = await query.ToListAsync();
                return items!;
            }
            catch
            {
                return null!;
            }
        }
    }
}
