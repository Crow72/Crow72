/* =========================================================
   بيانات تجريبية مشتركة بين النسختين (الهشّة والآمنة)
   - جدول مستخدمين في قاعدة SQLite داخل الذاكرة (لأجل مثال حقن SQL)
   - قائمة فواتير لكل مستخدم (لأجل مثال IDOR)
   كل البيانات وهمية وللتعلّم فقط.
   ========================================================= */

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

// قاعدة بيانات داخل الذاكرة — تُنشأ من جديد عند كل تشغيل
const db = new Database(":memory:");

db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    name     TEXT,
    email    TEXT,
    password TEXT,       -- تُستخدم في النسخة الهشّة (نص صريح) للتوضيح
    passwordHash TEXT    -- تُستخدم في النسخة الآمنة
  );
`);

// بذور المستخدمين (كلمات المرور وهمية للتعليم فقط)
const seedUsers = [
  { id: 1, name: "naif",  email: "naif@example.com",  password: "P@ssw0rd!" },
  { id: 2, name: "sara",  email: "sara@example.com",  password: "sara12345" },
  { id: 3, name: "admin", email: "admin@example.com", password: "admin-secret" },
];

const insert = db.prepare(
  "INSERT INTO users (id, name, email, password, passwordHash) VALUES (?, ?, ?, ?, ?)"
);
for (const u of seedUsers) {
  // في النسخة الآمنة نقارن مع passwordHash؛ نخزّن النص أيضًا فقط لتشغيل مثال النسخة الهشّة
  insert.run(u.id, u.name, u.email, u.password, bcrypt.hashSync(u.password, 10));
}

// فواتير: لكل فاتورة مالك (ownerId) — جوهر مثال IDOR
const invoices = [
  { id: 1001, ownerId: 1, amount: 250, note: "فاتورة نايف" },
  { id: 1002, ownerId: 2, amount: 980, note: "فاتورة سارة" },
  { id: 1003, ownerId: 3, amount: 5000, note: "فاتورة الأدمن" },
];

module.exports = { db, invoices, seedUsers };
