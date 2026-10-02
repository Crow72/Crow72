// =========================================================
// ✅ النسخة الآمنة (ASP.NET Core 8 — Minimal API)
// نفس وظائف النسخة الهشّة، لكن مع الإصلاحات الصحيحة للثغرات الثلاث.
// التشغيل:  dotnet run  →  http://localhost:5001
// =========================================================

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Unicode;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// في الإنتاج يأتي السرّ من متغيّر بيئة/خزنة أسرار، لا من الكود. هنا للتجربة فقط:
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")
                ?? "demo-secret-change-me-please-32chars-min";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));

builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Encoder = JavaScriptEncoder.Create(UnicodeRanges.All));

// مصادقة JWT: نتحقق من توقيع التوكن وصلاحيته
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false; // نُبقي اسم المطالبة "sub" كما هو
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.Zero,
        };
    });
builder.Services.AddAuthorization();

// تحديد المعدل: 5 محاولات دخول لكل IP خلال 15 دقيقة
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("login", ctx =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "anon",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(15),
                QueueLimit = 0,
            }));
});

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

var db = Db.Conn;

// -------- إصلاح 1: حقن SQL → استعلام مُعامَل --------
app.MapGet("/users", (string? name) =>
{
    using var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT id, name, email FROM users WHERE name = $name"; // ✅ معامل
    cmd.Parameters.AddWithValue("$name", name ?? "");
    var rows = new List<object>();
    using var r = cmd.ExecuteReader();
    while (r.Read())
        rows.Add(new { id = r.GetInt32(0), name = r.GetString(1), email = r.GetString(2) });
    return Results.Json(new { rows });
});

// -------- إصلاح 2: مصادقة سليمة --------
// BCrypt للتجزئة + JWT موقّع + تحديد المعدل + رسالة خطأ عامة.
app.MapPost("/login", (LoginDto dto) =>
{
    using var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT id, passwordHash FROM users WHERE email = $e";
    cmd.Parameters.AddWithValue("$e", dto.Email ?? "");

    int? userId = null;
    string? hash = null;
    using (var r = cmd.ExecuteReader())
        if (r.Read()) { userId = r.GetInt32(0); hash = r.GetString(1); }

    var ok = hash is not null && BCrypt.Net.BCrypt.Verify(dto.Password ?? "", hash);
    if (!ok || userId is null)
        return Results.Json(new { error = "بيانات الدخول غير صحيحة" }, statusCode: 401);

    var token = new JwtSecurityTokenHandler().CreateEncodedJwt(new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim("sub", userId.Value.ToString()) }),
        Expires = DateTime.UtcNow.AddMinutes(15),
        SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
    });
    return Results.Json(new { token });
})
.RequireRateLimiting("login");

// -------- إصلاح 3: تحقق من الهوية (JWT) ثم من الملكية --------
app.MapGet("/invoices/{id:int}", (int id, ClaimsPrincipal user) =>
{
    var sub = user.FindFirst("sub")?.Value;
    var inv = Db.Invoices.FirstOrDefault(i => i.Id == id);

    // 404 (لا 403) حتى لا نكشف وجود فاتورة لا يملكها المستخدم
    if (inv is null || sub is null || inv.OwnerId.ToString() != sub)
        return Results.Json(new { error = "غير موجودة" }, statusCode: 404);

    return Results.Json(inv);
})
.RequireAuthorization();

Console.WriteLine("✅ النسخة الآمنة تعمل على http://localhost:5001");
app.Run("http://localhost:5001");


// ---------------- بيانات تجريبية (وهمية) ----------------
record LoginDto(string? Email, string? Password);
record Invoice(int Id, int OwnerId, int Amount, string Note);

static class Db
{
    public static SqliteConnection Conn { get; } = Create();

    public static List<Invoice> Invoices { get; } = new()
    {
        new(1001, 1, 250,  "فاتورة نايف"),
        new(1002, 2, 980,  "فاتورة سارة"),
        new(1003, 3, 5000, "فاتورة الأدمن"),
    };

    static SqliteConnection Create()
    {
        var c = new SqliteConnection("Data Source=:memory:");
        c.Open();

        using (var create = c.CreateCommand())
        {
            create.CommandText =
                "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, passwordHash TEXT);";
            create.ExecuteNonQuery();
        }

        var users = new (int id, string name, string email, string pw)[]
        {
            (1, "naif",  "naif@example.com",  "P@ssw0rd!"),
            (2, "sara",  "sara@example.com",  "sara12345"),
            (3, "admin", "admin@example.com", "admin-secret"),
        };
        foreach (var u in users)
        {
            using var ins = c.CreateCommand();
            ins.CommandText = "INSERT INTO users (id, name, email, passwordHash) VALUES ($id, $n, $e, $h)";
            ins.Parameters.AddWithValue("$id", u.id);
            ins.Parameters.AddWithValue("$n", u.name);
            ins.Parameters.AddWithValue("$e", u.email);
            // ✅ نخزّن تجزئة bcrypt لا النص الصريح
            ins.Parameters.AddWithValue("$h", BCrypt.Net.BCrypt.HashPassword(u.pw));
            ins.ExecuteNonQuery();
        }
        return c;
    }
}
