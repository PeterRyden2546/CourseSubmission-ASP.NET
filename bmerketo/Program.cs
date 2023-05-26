using bmerketo.Contexts;
using bmerketo.Helpers.Repositories;
using bmerketo.Helpers.Services;
using bmerketo.Models.Identities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllersWithViews();

//Contexts
builder.Services.AddDbContext<IdentityDataContext>(x => x.UseSqlServer(builder.Configuration.GetConnectionString("IdentitySql")));

//Repositories
builder.Services.AddScoped<ProfileRepository>();
builder.Services.AddScoped<ContactRepository>();
builder.Services.AddScoped<CategoryRepository>();
builder.Services.AddScoped<TagRepository>();
builder.Services.AddScoped<ProductRepository>();
builder.Services.AddScoped<ProductTagRepository>();
builder.Services.AddScoped<ProductCategoryRepository>();


//Services
builder.Services.AddScoped<ContactService>();
builder.Services.AddScoped<RoleService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ProfileService>();
builder.Services.AddScoped<CategoryService>();
builder.Services.AddScoped<TagService>();
builder.Services.AddScoped<ProductService>();
builder.Services.AddScoped<HomeService>();


//Identities

builder.Services.AddIdentity<CustomIdentityUser, IdentityRole>(x =>
{
    x.SignIn.RequireConfirmedAccount = false;
    x.User.RequireUniqueEmail = true;
    x.Password.RequiredLength = 8;
})
        .AddEntityFrameworkStores<IdentityDataContext>();


var app = builder.Build();
app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
