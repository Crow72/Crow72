// =========================================================
// ❌ النسخة الهشّة (ASP.NET Core 8 — Minimal API)
// للتعلّم فقط. تحتوي عمدًا على ثلاث ثغرات شائعة لتوضيح الخطأ،
// وإصلاحها موجود في مشروع Secure.
// التشغيل:  dotnet run  →  http://localhost:5000
// =========================================================

using System.Text.Encodings.Web;
using System.Text.Unicode;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

// إظهار العربية في JSON بشكل مقروء (بدون \uXXXX)
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Encoder = JavaScriptEncoder.Create(UnicodeRanges.All));

var app = builder.Build();
var db = Db.Conn;

// -------- ثغرة 1: حقن SQL (SQL Injection) --------
// الخطأ: دمج مدخل المستخدم مباشرة في نص الاستعلام.
app.MapGet("/users", (string? name) =>
{
    name ??= "";
    var sql = $"SELECT id, name, email FROM users WHERE name = '{name}'"; // ❌ دمج نصّي
    using var cmd = db.CreateCommand();
    cmd.CommandText = sql;
    var rows = new List<object>();
    using var r = cmd.ExecuteReader();
    while (r.Read())
        rows.Add(new { id = r.GetInt32(0), name = r.GetString(1), email = r.GetString(2) });
    return Results.Json(new { sql, rows });
});

// -------- ثغرة 2: مصادقة مكسورة (Broken Authentication) --------
// الخطأ: كلمة مرور نص صريح + "توكن" = رقم المستخدم + بلا حدّ للمحاولات.
app.MapPost("/login", (LoginDto dto) =>
{
    using var cmd = db.CreateCommand();
    cmd.CommandText = "SELECT id, password FROM users WHERE email = $e";
    cmd.Parameters.AddWithValue("$e", dto.Email ?? "");
    using var r = cmd.ExecuteReader();
    if (r.Read() && r.GetString(1) == (dto.Password ?? "")) // ❌ مقارنة نص صريح
        return Results.Json(new { token = r.GetInt32(0).ToString() }); // ❌ توكن يمكن تخمينه
    return Results.Json(new { error = "بيانات خاطئة" }, statusCode: 401);
});

// -------- ثغرة 3: كسر التحكم بالوصول (IDOR) --------
// مصادقة ضعيفة: نثق بترويسة x-user-id. والأهم: لا نتحقق من مالك الفاتورة.
app.MapGet("/invoices/{id:int}", (int id, HttpContext ctx) =>
{
    var userId = ctx.Request.Headers["x-user-id"].ToString();
    if (string.IsNullOrEmpty(userId))
        return Results.Json(new { error = "أرسل ترويسة x-user-id" }, statusCode: 401);

    var inv = Db.Invoices.FirstOrDefault(i => i.Id == id);
    if (inv is null) return Results.Json(new { error = "غير موجودة" }, statusCode: 404);
    return Results.Json(inv); // ❌ لا تحقق من المالك — أي مستخدم يرى فاتورة غيره
});

Console.WriteLine("❌ النسخة الهشّة تعمل على http://localhost:5000  (للتعلّم فقط)");
app.Run("http://localhost:5000");


// ---------------- بيانات تجريبية (وهمية) ----------------
record LoginDto(string? Email, string? Password);
record Invoice(int Id, int OwnerId, int Amount, string Note);

static class Db
{
    // اتصال واحد بقاعدة SQLite داخل الذاكرة، يبقى مفتوحًا طوال عمر التطبيق
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
                "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT);";
            create.ExecuteNonQuery();
        }

        // كلمات المرور وهمية للتعليم فقط (نص صريح في النسخة الهشّة)
        var users = new (int id, string name, string email, string pw)[]
        {
            (1, "naif",  "naif@example.com",  "P@ssw0rd!"),
            (2, "sara",  "sara@example.com",  "sara12345"),
            (3, "admin", "admin@example.com", "admin-secret"),
        };
        foreach (var u in users)
        {
            using var ins = c.CreateCommand();
            ins.CommandText = "INSERT INTO users (id, name, email, password) VALUES ($id, $n, $e, $p)";
            ins.Parameters.AddWithValue("$id", u.id);
            ins.Parameters.AddWithValue("$n", u.name);
            ins.Parameters.AddWithValue("$e", u.email);
            ins.Parameters.AddWithValue("$p", u.pw);
            ins.ExecuteNonQuery();
        }
        return c;
    }
}
