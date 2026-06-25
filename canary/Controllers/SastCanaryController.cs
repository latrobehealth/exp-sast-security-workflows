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
/// Lives exclusively in latrobehealth/exp-sast-security-workflows.
/// Analysed by the verify-canary CI job to confirm CodeQL security-extended
/// detects each class.  NEVER deployed to any environment.
///
/// Pattern rationale is documented per-action below.
/// </summary>
[ApiController]
[Route("_sast-canary")]
public sealed class SastCanaryController : ControllerBase
{
    private readonly CanaryDbContext                _db;
    private readonly ILogger<SastCanaryController> _logger;
    private static readonly HttpClient             _http = new();

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
    /// Rule: cs/path-injection
    /// Pattern: [FromQuery] string → Path.Combine → File.ReadAllText
    /// Confirmed detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpGet("a01/file")]
    public IActionResult GetFile([FromQuery] string fileName)
    {
        var content = System.IO.File.ReadAllText(
            System.IO.Path.Combine("C:\\data", fileName));
        return Ok(content);
    }

    /// <summary>
    /// A01-b  Missing function-level access control.
    /// Rule: cs/web/missing-function-level-access-control
    /// Pattern: HTTP DELETE action on a class with no [Authorize] anywhere.
    /// Confirmed detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpDelete("a01/admin-delete/{id:int}")]
    public async Task<IActionResult> AdminDelete(int id)
    {
        var item = await _db.Items.FindAsync(id);
        if (item is null) return NotFound();
        _db.Items.Remove(item);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A02 — Cryptographic Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A02-a  Weak encryption algorithm — DES.
    /// Rule: cs/weak-encryption
    /// Pattern: DES.Create() — DES is a deprecated 56-bit symmetric cipher.
    /// NOTE: MD5/SHA-1 are hash functions, not encryption algorithms.
    ///       In csharp-queries ≥ 1.7.4 cs/weak-encryption only fires on weak
    ///       ENCRYPTION ciphers (DES, 3DES, RC4).  Hash functions do not trigger it.
    /// </summary>
    [HttpPost("a02/encrypt")]
    public IActionResult EncryptData([FromBody] string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);

        using var des = DES.Create();                         // cs/weak-encryption — DES is a weak cipher
        des.GenerateKey();
        des.GenerateIV();
        using var encryptor = des.CreateEncryptor();
        using var ms = new System.IO.MemoryStream();
        using var cs = new System.Security.Cryptography.CryptoStream(
            ms, encryptor, System.Security.Cryptography.CryptoStreamMode.Write);
        cs.Write(bytes, 0, bytes.Length);
        cs.FlushFinalBlock();
        return Ok(Convert.ToBase64String(ms.ToArray()));
    }

    /// <summary>
    /// A02-b  Hardcoded credential in SMTP client.
    /// Rule: cs/hardcoded-credentials
    /// Pattern: literal password — NetworkCredential — SmtpClient.Credentials — smtp.Send()
    /// SmtpClient.Credentials is a tracked authentication sink in CodeQL C#.
    /// The smtp.Send() call ensures the credential flows into a real network I/O operation.
    /// </summary>
    [HttpGet("a02/connect")]
    public IActionResult HardcodedCredential()
    {
#pragma warning disable SYSLIB0006 // SmtpClient is obsolete but available; used as a CodeQL canary sink
        using var smtp = new System.Net.Mail.SmtpClient("mail.prod.example.com", 587)
        {
            EnableSsl   = true,
            Credentials = new NetworkCredential("svc@example.com", "Hardcoded@Pass2025!")
        };
        smtp.Send("svc@example.com", "admin@example.com", "canary", "test");
#pragma warning restore SYSLIB0006
        return Ok("sent");
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A03 — Injection
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A03-a  SQL injection via EF Core FromSqlRaw.
    /// Rule: cs/sql-injection
    /// Pattern: [FromQuery] string → string concatenation → FromSqlRaw
    /// Confirmed detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpGet("a03/search")]
    public IActionResult Search([FromQuery] string term)
    {
        var results = _db.Items
            .FromSqlRaw("SELECT * FROM Items WHERE Name = '" + term + "'")
            .ToList();
        return Ok(results);
    }

    /// <summary>
    /// A03-b  OS command injection via Process.Start.
    /// Rule: cs/command-line-injection
    /// Pattern: [FromQuery] string → ProcessStartInfo arguments
    /// Confirmed detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpGet("a03/ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 1 " + host)
        {
            RedirectStandardOutput = true,
            UseShellExecute        = false
        };
        using var proc = Process.Start(psi)!;
        return Ok(proc.StandardOutput.ReadToEnd());
    }

    /// <summary>
    /// A03-c  Reflected XSS — documentation pattern only.
    /// Rule: cs/web/xss
    /// Pattern: [FromQuery] string → HttpResponse.WriteAsync (direct HTML write)
    /// NOTE: Neither ContentResult nor Response.WriteAsync is modelled as an XSS sink
    ///       in csharp-queries 1.7.4 for ASP.NET Core 9.  This pattern is kept for
    ///       documentation and future suite improvements but is listed as BONUS in
    ///       verify-canary.py until the query models ASP.NET Core output sinks.
    /// </summary>
    [HttpGet("a03/greet")]
    public async Task Greet([FromQuery] string name)
    {
        Response.ContentType = "text/html";
        await Response.WriteAsync("<h1>Hello " + name + "</h1>");
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A05 — Security Misconfiguration
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A05-a  Open / unvalidated redirect.
    /// Rule: cs/web/unvalidated-url-redirect
    /// Pattern: [FromQuery] string → Redirect()
    /// Confirmed detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpGet("a05/redirect")]
    public IActionResult DoRedirect([FromQuery] string returnUrl)
        => Redirect(returnUrl);

    /// <summary>
    /// A05-b  Stack trace exposed to caller (BONUS — needs security-and-quality suite).
    /// Rule: cs/stack-trace-exposure
    /// Not in security-extended; included for documentation only.
    /// </summary>
    [HttpGet("a05/diagnostics")]
    public IActionResult Diagnostics()
    {
        try   { throw new InvalidOperationException("Diagnostic probe."); }
        catch (Exception ex) { return Ok(new { error = ex.ToString() }); }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A07 — Identification and Authentication Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A07-a  Plaintext credentials written to log.
    /// Rule: cs/log-forging
    /// Pattern: [FromQuery] string password → LogInformation structured arg
    /// Uses [FromQuery] (not [FromBody] + record) to keep taint path simple
    /// and avoid any CodeQL modelling gap with positional record properties.
    /// Confirmed equivalent pattern detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpPost("a07/login")]
    public IActionResult Login([FromQuery] string username, [FromQuery] string password)
    {
        _logger.LogInformation(
            "Login attempt — user={User} password={Pass}", username, password);
        return Ok();
    }

    /// <summary>
    /// A07-b  Bearer token value written to debug log.
    /// Rule: cs/log-forging
    /// Pattern: Request.Headers["Authorization"] → LogDebug structured arg
    /// </summary>
    [HttpGet("a07/token-info")]
    public IActionResult TokenInfo()
    {
        var token = Request.Headers["Authorization"].ToString();
        _logger.LogDebug("Received bearer token: {Token}", token);
        return Ok();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A08 — Software and Data Integrity Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A08-a  XPath injection.
    /// Rule: cs/xml-injection
    /// Pattern: [FromQuery] string → string concatenation inside SelectSingleNode XPath
    ///
    /// IMPORTANT DISTINCTION:
    ///   cs/xml-injection  = XPath injection (user input inside an XPath expression)
    ///   XXE               = separate vulnerability; not reliably detected by security-extended
    ///                       because Request.Body (Stream) is not modelled as a taint source.
    ///
    /// A static XML document is loaded so the file-read taint path stays clean;
    /// the injection is in the query expression, not the document source.
    /// </summary>
    [HttpGet("a08/xpath")]
    public IActionResult XPath([FromQuery] string id)
    {
        var doc = new XmlDocument();
        doc.LoadXml("<users><user id='1' role='admin'/><user id='2' role='guest'/></users>");
        // User-controlled value concatenated directly into XPath expression
        var node = doc.SelectSingleNode("//user[@id='" + id + "']");
        return Ok(node?.OuterXml);
    }

    /// <summary>
    /// A08-b  XXE via XmlUrlResolver (BONUS — taint from Request.Body stream not
    /// modelled by security-extended; kept for documentation and security-and-quality runs).
    /// </summary>
    [HttpPost("a08/import-xml")]
    public IActionResult ImportXml()
    {
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.Load(Request.Body);
        return Ok(doc.DocumentElement?.Name);
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A09 — Security Logging and Monitoring Failures
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A09-a  Log injection — raw request path injected into structured log.
    /// Rule: cs/log-forging
    /// Pattern: Request.Path → LogInformation structured arg (no sanitisation)
    /// Confirmed equivalent pattern detected in test/owasp-sast-validation scan.
    /// </summary>
    [HttpGet("a09/log-path")]
    public IActionResult LogPath()
    {
        _logger.LogInformation("Visited: {Path}", Request.Path.Value);
        return Ok();
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // A10 — Server-Side Request Forgery (SSRF)
    // ══════════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// A10-a  SSRF — user-controlled URL passed to HttpClient (BONUS).
    /// Rule: cs/ssrf
    /// Not detected by current security-extended suite; HttpClient is not yet
    /// modelled as an SSRF sink in CodeQL C# pack.  Kept for future suite upgrades.
    /// </summary>
    [HttpGet("a10/fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        var body = await _http.GetStringAsync(url);
        return Ok(body);
    }
}
