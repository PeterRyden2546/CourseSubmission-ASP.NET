using bmerketo.Contexts;
using bmerketo.Models.Entities;

namespace bmerketo.Helpers.Repositories
{
    public class ContactRepository : Repo<ContactEntity>
    {
        public ContactRepository(IdentityDataContext dataContext) : base(dataContext)
        {
        }

    }
}
