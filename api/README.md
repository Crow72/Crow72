# أمثلة الـ API — هشّ مقابل آمن

مثالان بـ Node.js يوضّحان **ثلاث ثغرات** شائعة وكيفية إصلاحها. للتعلّم فقط.

> ⚠️ النسخة الهشّة (`insecure-api.js`) تحتوي ثغرات عمدًا. شغّلها على جهازك للتعلّم فقط،
> ولا تنشرها على الإنترنت، ولا تجرّب أي هجوم على نظام لا تملكه.

## التشغيل

```bash
cd api
npm install

# النسخة الهشّة (منفذ 3000)
npm run insecure

# في طرفية أخرى: النسخة الآمنة (منفذ 3001)
npm run secure
```

## قارن بنفسك

### 1) حقن SQL
نستخدم `-G --data-urlencode` ليتولّى curl ترميز الرابط (المسافات والرموز):
```bash
# ❌ الهشّة: الشرط يصبح صحيحًا دائمًا فترجع كل المستخدمين
curl -s -G "http://localhost:3000/users" --data-urlencode "name=' OR '1'='1"

# ✅ الآمنة: rows = [] — القيمة عوملت كنص لا كأمر
curl -s -G "http://localhost:3001/users" --data-urlencode "name=' OR '1'='1"
```

### 2) مصادقة
```bash
# ❌ الهشّة: التوكن = رقم المستخدم (يمكن تخمينه)
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"naif@example.com","password":"P@ssw0rd!"}'

# ✅ الآمنة: توكن JWT موقّع + حد 5 محاولات
curl -X POST http://localhost:3001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"naif@example.com","password":"P@ssw0rd!"}'
```

### 3) IDOR (كسر التحكم بالوصول)
```bash
# ❌ الهشّة: المستخدم 1 يقرأ فاتورة المستخدم 2 بسهولة!
curl http://localhost:3000/invoices/1002 -H "x-user-id: 1"

# ✅ الآمنة: نسجّل الدخول، نأخذ التوكن، ثم نحاول قراءة فاتورة غيرنا
TOKEN=$(curl -s -X POST http://localhost:3001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"naif@example.com","password":"P@ssw0rd!"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# فاتورتنا (1001) ترجع، وفاتورة غيرنا (1002) ترجع 404
curl http://localhost:3001/invoices/1001 -H "Authorization: Bearer $TOKEN"
curl http://localhost:3001/invoices/1002 -H "Authorization: Bearer $TOKEN"
```

## الثغرات والإصلاحات

| # | الثغرة | الإصلاح |
|---|--------|---------|
| 1 | حقن SQL بدمج النصوص | استعلامات مُعامَلة `?` |
| 2 | كلمة مرور نص صريح + توكن مخمَّن | `bcrypt` + `JWT` + تحديد المعدل |
| 3 | IDOR بلا تحقق من المالك | التحقق من ملكية المورد على الخادم |
