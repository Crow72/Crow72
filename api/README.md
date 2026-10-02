# أمثلة الـ API — هشّ مقابل آمن (ASP.NET Core 8)

مشروعان بـ C# / ASP.NET Core يوضّحان **ثلاث ثغرات** شائعة وكيفية إصلاحها. للتعلّم فقط.

> ⚠️ مشروع `Insecure` يحتوي ثغرات عمدًا. شغّله على جهازك للتعلّم فقط،
> ولا تنشره على الإنترنت، ولا تجرّب أي هجوم على نظام لا تملكه.

## المتطلبات
- [.NET SDK 8](https://dotnet.microsoft.com/download) أو أحدث.

## التشغيل

```bash
# النسخة الهشّة (منفذ 5000)
dotnet run --project Insecure

# في طرفية أخرى: النسخة الآمنة (منفذ 5001)
dotnet run --project Secure
```

## قارن بنفسك

### 1) حقن SQL
نستخدم `-G --data-urlencode` ليتولّى curl ترميز الرابط (المسافات والرموز):
```bash
# ❌ الهشّة: الشرط يصبح صحيحًا دائمًا فترجع كل المستخدمين
curl -s -G "http://localhost:5000/users" --data-urlencode "name=' OR '1'='1"

# ✅ الآمنة: rows = [] — القيمة عوملت كنص لا كأمر
curl -s -G "http://localhost:5001/users" --data-urlencode "name=' OR '1'='1"
```

### 2) مصادقة
```bash
# ❌ الهشّة: التوكن = رقم المستخدم (يمكن تخمينه)
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"naif@example.com","password":"P@ssw0rd!"}'

# ✅ الآمنة: توكن JWT موقّع + حد 5 محاولات لكل IP
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"naif@example.com","password":"P@ssw0rd!"}'
```

### 3) IDOR (كسر التحكم بالوصول)
```bash
# ❌ الهشّة: المستخدم 1 يقرأ فاتورة المستخدم 2 بسهولة!
curl http://localhost:5000/invoices/1002 -H "x-user-id: 1"

# ✅ الآمنة: نسجّل الدخول، نأخذ التوكن، ثم نحاول قراءة فاتورة غيرنا
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"naif@example.com","password":"P@ssw0rd!"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# فاتورتنا (1001) ترجع، وفاتورة غيرنا (1002) ترجع 404
curl http://localhost:5001/invoices/1001 -H "Authorization: Bearer $TOKEN"
curl http://localhost:5001/invoices/1002 -H "Authorization: Bearer $TOKEN"
```

## بنية المشروع

```
api/
├── Insecure/   ← النسخة الهشّة (Program.cs فيه الثغرات الثلاث)
└── Secure/     ← النسخة الآمنة (نفس الوظائف بعد الإصلاح)
```

## الثغرات والإصلاحات

| # | الثغرة | الإصلاح |
|---|--------|---------|
| 1 | حقن SQL بدمج النصوص | استعلامات مُعامَلة (`Parameters`) |
| 2 | كلمة مرور نص صريح + توكن مخمَّن | `BCrypt` + `JWT` + تحديد المعدل المدمج |
| 3 | IDOR بلا تحقق من المالك | التحقق من ملكية المورد عبر مطالبات التوكن |

## التقنيات
- ASP.NET Core 8 (Minimal API)
- `Microsoft.Data.Sqlite` (قاعدة بيانات داخل الذاكرة)
- `BCrypt.Net-Next` (تجزئة كلمات المرور)
- `Microsoft.AspNetCore.Authentication.JwtBearer` (مصادقة JWT)
- `RateLimiter` المدمج في ASP.NET Core (تحديد المعدل)
