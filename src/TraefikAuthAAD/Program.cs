using TraefikAuthAAD;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpContextAccessor();
builder.Services.Configure<AzureAD>(builder.Configuration.GetSection("AzureAD"));
builder.Services.AddScoped<RequestHandler>();

var app = builder.Build();

app.MapGet("/auth", async context =>
{
    var handler = context.RequestServices.GetRequiredService<RequestHandler>();
    await handler.HandleAsync();
});

app.Run();
