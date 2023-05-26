using bmerketo.Contexts;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace bmerketo.Helpers.Repositories;

public abstract class Repo<TEntity> where TEntity : class
{
    protected readonly IdentityDataContext _dataContext;

    protected Repo(IdentityDataContext dataContext)
    {
        _dataContext=dataContext;
    }

    public virtual async Task<TEntity> AddAsync(TEntity entity)
    {
        try
        {
            _dataContext.Set<TEntity>().Add(entity);
            await _dataContext.SaveChangesAsync();
            return entity;
        }
        catch { return null!; }
    }

    public virtual async Task<TEntity> GetAsync(Expression<Func<TEntity, bool>> predicate)
    {
        try
        {
            var item = await _dataContext.Set<TEntity>().FirstOrDefaultAsync(predicate);
            return item!;
        }
        catch { return null!; }
    }


    public virtual async Task<IEnumerable<TEntity>> GetAllAsync()
    {
        try
        {
            var items = await _dataContext.Set<TEntity>().ToListAsync();
            return items;
        }
        catch { return null!; }
    }

    public virtual async Task<IEnumerable<TEntity>> GetAllAsync(Expression<Func<TEntity, bool>> predicate)
    {
        try
        {
            var items = await _dataContext.Set<TEntity>().Where(predicate).ToListAsync();
            return items;
        }
        catch { return null!; }
    }

    public virtual async Task<TEntity> UpdateAsync(TEntity entity)
    {
        try
        {
            _dataContext.Set<TEntity>().Update(entity);
            await _dataContext.SaveChangesAsync();
            return entity;
        }
        catch { return null!; }
    }

    public virtual async Task<bool> DeleteAsync(TEntity entity)
    {
        try
        {
            _dataContext.Set<TEntity>().Remove(entity);
            await _dataContext.SaveChangesAsync();
            return true;
        }
        catch { return false; }

    }
}
