/* =========================================================
   ✅ النسخة الآمنة — نفس الوظائف، لكن مع الإصلاحات الصحيحة
   تعالج الثغرات الثلاث الموجودة في insecure-api.js.
   التشغيل: npm run secure  →  http://localhost:3001
   ========================================================= */

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { db, invoices } = require("./data");

const app = express();
app.use(express.json());

const PORT = 3001;
// في الإنتاج يأتي السرّ من متغيّر بيئة، لا من الكود. هنا للتجربة فقط:
const JWT_SECRET = process.env.JWT_SECRET || "demo-secret-change-me";

/* -------- إصلاح 1: حقن SQL → استعلام مُعامَل -------- */
app.get("/users", (req, res) => {
  const name = req.query.name || "";
  // القيمة تُمرَّر كبيانات عبر ? ولا تصبح جزءًا من أمر SQL
  const rows = db
    .prepare("SELECT id, name, email FROM users WHERE name = ?")
    .all(name);
  res.json({ rows });
});

/* -------- إصلاح 2: مصادقة سليمة --------
   bcrypt للتجزئة + JWT موقّع + حد للمحاولات + رسالة خطأ عامة. */
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 5,                    // 5 محاولات لكل IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "محاولات كثيرة، حاول لاحقًا" },
});

app.post("/login", loginRateLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  const ok = user && (await bcrypt.compare(password || "", user.passwordHash));
  if (!ok) return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });

  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: "15m" });
  res.json({ token });
});

/* -------- إصلاح 3: تحقق من الهوية (JWT) ثم من الملكية -------- */
function authRequired(req, res, next) {
  const header = req.header("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "توكن مفقود" });
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { sub: userId }
    next();
  } catch {
    res.status(401).json({ error: "توكن غير صالح" });
  }
}

app.get("/invoices/:id", authRequired, (req, res) => {
  const invoice = invoices.find((i) => i.id === Number(req.params.id));
  // 404 (لا 403) حتى لا نكشف وجود فاتورة لا يملكها المستخدم
  if (!invoice || invoice.ownerId !== req.user.sub) {
    return res.status(404).json({ error: "غير موجودة" });
  }
  res.json(invoice);
});

app.listen(PORT, () => {
  console.log(`✅ النسخة الآمنة تعمل على http://localhost:${PORT}`);
});
