using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Teeckbox.Agent.Tests;

/// <summary>A system on "the internal network": a server on the local machine that the agent is asked to call.</summary>
internal sealed class TestTarget : IAsyncDisposable
{
    private readonly WebApplication _app;

    public ConcurrentQueue<string> Paths { get; } = new();

    public int TokenRequests;

    private TestTarget(WebApplication app) => _app = app;

    public string Url => _app.Urls.First();

    public int Port => new Uri(Url).Port;

    public int Hits => Paths.Count;

    public static async Task<TestTarget> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        var app = builder.Build();
        var target = new TestTarget(app);

        app.Use(async (context, next) =>
        {
            target.Paths.Enqueue(context.Request.Path);
            await next();
        });
        app.MapGet("/hello", () => "hello");
        app.MapGet("/paged", (HttpContext context) =>
        {
            context.Response.Headers.Link = "<http://127.0.0.1/items?page=2>; rel=\"next\"";
            context.Response.Headers["X-Secret"] = "hunter2";
            return "page one";
        });
        app.MapGet("/limited", (HttpContext context) =>
        {
            context.Response.Headers.RetryAfter = "7";
            return Results.Text("slow down", statusCode: 429);
        });
        app.MapGet("/echo", (HttpContext context) => $"{context.Request.Headers.Authorization}|{context.Request.Headers["X-Tenant"]}|{context.Request.Headers.Accept}");
        app.MapPost("/echo-body", async (HttpContext context) => $"{context.Request.ContentType}|{await new StreamReader(context.Request.Body).ReadToEndAsync()}");
        app.MapGet("/redirect", () => Results.Redirect("http://127.0.0.2:1/elsewhere"));
        app.MapGet("/big", () => new string('x', 2 * 1024 * 1024));
        app.MapGet("/delay", async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(1));
            return "done";
        });
        app.MapGet("/slow", async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10));
            return "late";
        });
        app.MapGet("/fail", () => Results.Text("secret-error-detail: password=hunter2", statusCode: 500));
        app.MapPost("/token", () =>
        {
            Interlocked.Increment(ref target.TokenRequests);
            return Results.Json(new { access_token = "token-from-endpoint", expires_in = 3600 });
        });

        await app.StartAsync();
        return target;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
