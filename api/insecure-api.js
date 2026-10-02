/* =========================================================
   ❌ النسخة الهشّة — للتعلّم فقط، لا تنشرها في بيئة حقيقية
   تحتوي عمدًا على ثلاث ثغرات شائعة لتوضيح الخطأ ثم إصلاحه
   في الملف الآمن (secure-api.js).
   التشغيل: npm run insecure  →  http://localhost:3000
   ========================================================= */

const express = require("express");
const { db, invoices } = require("./data");

const app = express();
app.use(express.json());

const PORT = 3000;

/* -------- ثغرة 1: حقن SQL (SQL Injection) --------
   الخطأ: دمج مدخل المستخدم مباشرة في نص الاستعلام. */
app.get("/users", (req, res) => {
  const name = req.query.name || "";
  const sql = `SELECT id, name, email FROM users WHERE name = '${name}'`;
  try {
    const rows = db.prepare(sql).all(); // الاستعلام مبني من نص المستخدم!
    res.json({ sql, rows });
  } catch (e) {
    res.status(500).json({ sql, error: e.message });
  }
});

/* -------- ثغرة 2: مصادقة مكسورة (Broken Authentication) --------
   الخطأ: كلمة مرور بنص صريح + توكن = رقم المستخدم + بلا حد للمحاولات. */
app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (user && user.password === password) {
    return res.json({ token: String(user.id) }); // "توكن" يمكن تخمينه
  }
  res.status(401).json({ error: "بيانات خاطئة" });
});

/* -------- ثغرة 3: كسر التحكم بالوصول (IDOR) --------
   مصادقة ضعيفة: نثق بترويسة x-user-id كما هي.
   والأهم: لا نتحقق أن الفاتورة تخص المستخدم الحالي. */
function authInsecure(req, res, next) {
  const userId = Number(req.header("x-user-id"));
  if (!userId) return res.status(401).json({ error: "أرسل ترويسة x-user-id" });
  req.user = { id: userId };
  next();
}

app.get("/invoices/:id", authInsecure, (req, res) => {
  const invoice = invoices.find((i) => i.id === Number(req.params.id));
  if (!invoice) return res.status(404).json({ error: "غير موجودة" });
  res.json(invoice); // ❌ لا تحقق من المالك — أي مستخدم يرى فاتورة غيره
});

app.listen(PORT, () => {
  console.log(`❌ النسخة الهشّة تعمل على http://localhost:${PORT}`);
  console.log("   جرّب أمثلة الهجوم في api/README.md — ثم قارنها بالنسخة الآمنة.");
});
