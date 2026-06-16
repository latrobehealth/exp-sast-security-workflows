// SAST canary entry point — compiled for CodeQL analysis only, never deployed.
using Microsoft.EntityFrameworkCore;
using Sast.Canary.Data;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddDbContext<CanaryDbContext>(o => o.UseInMemoryDatabase("canary"));

var app = builder.Build();
app.MapControllers();
app.Run();
