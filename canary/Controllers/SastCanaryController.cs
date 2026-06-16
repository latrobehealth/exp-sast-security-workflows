using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sast.Canary.Data;

namespace Sast.Canary.Controllers;

/// <summary>
/// SAST CANARY — intentional OWASP Top 10:2025 vulnerabilities.
///
/// This controller lives exclusively in latrobehealth/exp-sast-security-workflows
/// and is analysed by the verify-canary CI job to confirm the CodeQL
/// security-extended query suite detects each vulnerability class.
/// It is NEVER deployed to any environment.
///
/// Each action maps to one OWASP category + one CodeQL rule ID.
/// </summary>
[ApiController]
[Route("_sast-canary")]
public sealed class SastCanaryController : ControllerBase
{
    private readonly CanaryDbContext                 _db;
    private readonly ILogger<SastCanaryController>  _logger;
    private static  readonly HttpClient             _http = new();

    public SastCanaryController(CanaryDbContext db, ILogger<SastCanaryController> logger)
    {
        _db     = db;
        _logger = logger;
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A01 — Broken Access Control
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A01-a  Path traversal.
    /// CodeQL rule: cs/path-injection
    /// User-supplied filename appended to a base path without sanitisation.
    /// </summary>
    [HttpGet("a01/file")]
    public IActionResult GetFile([FromQuery] string fileName)
    {
        var content = System.IO.File.ReadAllText(
            System.IO.Path.Combine("C:\\data", fileName));  // cs/path-injection
        return Ok(content);
    }

    /// <summary>
    /// A01-b  Missing function-level access control.
    /// CodeQL rule: cs/web/missing-function-level-access-control
    /// Admin delete action with no [Authorize] attribute.
    /// </summary>
    [HttpDelete("a01/admin-delete/{id:int}")]
    public async Task<IActionResult> AdminDelete(int id)
    {
        var item = await _db.Items.FindAsync(id);           // cs/web/missing-function-level-access-control
        if (item is null) return NotFound();
        _db.Items.Remove(item);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A02 — Cryptographic Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A02-a  Weak hash algorithm (MD5).
    /// CodeQL rule: cs/use-of-broken-or-weak-cryptographic-algorithm
    /// </summary>
    [HttpPost("a02/hash")]
    public IActionResult HashData([FromBody] string input)
    {
        using var md5  = MD5.Create();                      // cs/use-of-broken-or-weak-cryptographic-algorithm
        var       hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
        return Ok(Convert.ToHexString(hash));
    }

    /// <summary>
    /// A02-b  Hardcoded credential passed to a network API.
    /// CodeQL rule: cs/hardcoded-credentials
    /// </summary>
    [HttpGet("a02/connect")]
    public IActionResult HardcodedCredential()
    {
        var cred = new NetworkCredential("sa", "Hardcoded@Pass2025!");  // cs/hardcoded-credentials
        return Ok(cred.UserName);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A03 — Injection
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A03-a  SQL injection via EF Core FromSqlRaw.
    /// CodeQL rule: cs/sql-injection
    /// </summary>
    [HttpGet("a03/search")]
    public IActionResult Search([FromQuery] string term)
    {
        var results = _db.Items
            .FromSqlRaw("SELECT * FROM Items WHERE Name = '" + term + "'")  // cs/sql-injection
            .ToList();
        return Ok(results);
    }

    /// <summary>
    /// A03-b  OS command injection via Process.Start.
    /// CodeQL rule: cs/command-line-injection
    /// </summary>
    [HttpGet("a03/ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        var psi = new ProcessStartInfo("cmd.exe", $"/c ping -n 1 {host}")  // cs/command-line-injection
        {
            RedirectStandardOutput = true,
            UseShellExecute        = false
        };
        using var proc = Process.Start(psi)!;
        return Ok(proc.StandardOutput.ReadToEnd());
    }

    /// <summary>
    /// A03-c  Reflected XSS — user input rendered as raw HTML.
    /// CodeQL rule: cs/web/xss
    /// </summary>
    [HttpGet("a03/greet")]
    public ContentResult Greet([FromQuery] string name)
        => Content($"<h1>Hello {name}</h1>", "text/html");  // cs/web/xss

    // ══════════════════════════════════════════════════════════════════════════════
    // A05 — Security Misconfiguration
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A05-a  Open / unvalidated redirect.
    /// CodeQL rule: cs/web/unvalidated-url-redirect
    /// </summary>
    [HttpGet("a05/redirect")]
    public IActionResult DoRedirect([FromQuery] string returnUrl)
        => Redirect(returnUrl);                             // cs/web/unvalidated-url-redirect

    /// <summary>
    /// A05-b  Stack-trace / internal detail leaked to caller.
    /// CodeQL rule: cs/stack-trace-exposure  (security-and-quality suite)
    /// </summary>
    [HttpGet("a05/diagnostics")]
    public IActionResult Diagnostics()
    {
        try   { throw new InvalidOperationException("Diagnostic probe."); }
        catch (Exception ex) { return Ok(new { error = ex.ToString() }); } // stack-trace exposure
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A07 — Identification and Authentication Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A07-a  Plaintext credentials written to the application log.
    /// CodeQL rule: cs/log-forging  (credential/sensitive-data variant)
    /// </summary>
    [HttpPost("a07/login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        _logger.LogInformation(                             // cs/log-forging
            "Login attempt — user={User} password={Pass}",
            req.Username, req.Password);
        return Ok();
    }

    /// <summary>
    /// A07-b  Bearer token value written to debug log.
    /// CodeQL rule: cs/log-forging
    /// </summary>
    [HttpGet("a07/token-info")]
    public IActionResult TokenInfo()
    {
        var token = Request.Headers.Authorization.ToString();
        _logger.LogDebug("Received bearer token: {Token}", token);  // cs/log-forging
        return Ok();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A08 — Software and Data Integrity Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A08-a  XML External Entity (XXE) via XmlUrlResolver.
    /// CodeQL rule: cs/xml-injection
    /// </summary>
    [HttpPost("a08/import-xml")]
    public IActionResult ImportXml()
    {
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };  // cs/xml-injection
        doc.Load(Request.Body);
        return Ok(doc.DocumentElement?.Name);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A09 — Security Logging and Monitoring Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A09-a  Log injection — raw request path injected into structured log.
    /// CodeQL rule: cs/log-forging
    /// </summary>
    [HttpGet("a09/log-path")]
    public IActionResult LogPath()
    {
        _logger.LogInformation("Visited: {Path}", Request.Path.Value);  // cs/log-forging
        return Ok();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A10 — Server-Side Request Forgery (SSRF)
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A10-a  SSRF — user-controlled URL fetched without allowlist validation.
    /// CodeQL rule: cs/ssrf  (coverage depends on CodeQL model version)
    /// </summary>
    [HttpGet("a10/fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        var body = await _http.GetStringAsync(url);         // cs/ssrf
        return Ok(body);
    }
}

public sealed record LoginRequest(string Username, string Password);
