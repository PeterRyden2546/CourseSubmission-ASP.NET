using bmerketo.Contexts;
using bmerketo.Models.Entities;

namespace bmerketo.Helpers.Repositories
{
    public class ProfileRepository : Repo<ProfileEntity>
    {
        public ProfileRepository(IdentityDataContext dataContext) : base(dataContext)
        {
        }
    }
}
