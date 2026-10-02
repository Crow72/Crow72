/* =========================================================
   أمن واجهات الـ API — منطق الصفحة
   - بيانات المقارنات الثلاث
   - بناء البطاقات + تبويبات (هشّ / آمن)
   - أزرار نسخ الكود
   - اختبار قصير تفاعلي
   ملاحظة: نستخدم textContent لإدراج الكود، فيتم تهريب الرموز تلقائيًا.
   ========================================================= */

const comparisons = [
  {
    id: "sqli",
    owasp: "OWASP API8:2023 — Injection",
    title: "حقن SQL",
    en: "SQL Injection",
    risk: "دمج مدخلات المستخدم مباشرة داخل استعلام قاعدة البيانات يسمح للمهاجم بتغيير منطق الاستعلام، فيقرأ أو يحذف بيانات لا تخصّه.",
    vuln: `// ❌ هشّ: ندمج مدخل المستخدم (name) مباشرة في نص الاستعلام
app.get("/users", (req, res) => {
  const name = req.query.name;
  // الخطأ: القيمة تصبح جزءًا من أمر SQL نفسه
  const sql = \`SELECT id, name, email FROM users WHERE name = '\${name}'\`;
  db.all(sql, (err, rows) => res.json(rows));
});`,
    attack:
      'الطلب <code>?name=\' OR \'1\'=\'1</code> يحوّل الشرط إلى صحيح دائمًا، فيعيد <strong>كل</strong> المستخدمين. وبصيغة <code>UNION</code> يمكن سحب جداول أخرى كليًا.',
    secure: `// ✅ آمن: استعلام مُعامَل — القيمة تُمرَّر كبيانات لا كأمر
app.get("/users", (req, res) => {
  const name = req.query.name;
  const sql = "SELECT id, name, email FROM users WHERE name = ?";
  db.all(sql, [name], (err, rows) => res.json(rows)); // ? مكان آمن للقيمة
});`,
    lesson:
      "لا تبنِ الاستعلام بدمج النصوص أبدًا. استخدم الاستعلامات المُعامَلة (Prepared Statements)، وتحقّق من نوع المدخلات، وامنح مستخدم قاعدة البيانات أقل صلاحيات ممكنة.",
  },
  {
    id: "auth",
    owasp: "OWASP API2:2023 — Broken Authentication",
    title: "مصادقة مكسورة",
    en: "Broken Authentication",
    risk: "تخزين كلمات المرور كنص صريح، وإصدار توكن يمكن تخمينه، وعدم تحديد عدد المحاولات، كلها تفتح الباب لتسريب الحسابات والتخمين العنيف.",
    vuln: `// ❌ هشّ: كلمة المرور نص صريح + توكن = معرّف يمكن تخمينه + بلا حد للمحاولات
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (user && user.password === password) {   // مقارنة نص صريح
    return res.json({ token: user.id });        // "توكن" = رقم المستخدم!
  }
  res.status(401).json({ error: "بيانات خاطئة" });
});`,
    attack:
      'تسريب قاعدة البيانات يكشف كل كلمات المرور فورًا. والتوكن <code>= user.id</code> يمكن تخمينه (1، 2، 3…) لانتحال أي مستخدم. وغياب الحد يسمح بتجربة ملايين كلمات المرور.',
    secure: `// ✅ آمن: تجزئة bcrypt + توكن JWT موقّع + حد للمحاولات + رسالة عامة
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

app.post("/login", loginRateLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  // bcrypt.compare تقارن بأمان ولو كان المستخدم غير موجود (نحميه من تسريب التوقيت)
  const ok = user && await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });

  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });
  res.json({ token });
});`,
    lesson:
      "خزّن تجزئة كلمة المرور بـ bcrypt أو argon2 (لا النص). وقّع التوكن بمفتاح سرّي مع صلاحية قصيرة. حدّد معدل المحاولات، واجعل رسالة الخطأ عامة حتى لا تكشف أي الحقلين خاطئ.",
  },
  {
    id: "idor",
    owasp: "OWASP API1:2023 — Broken Object Level Authorization",
    title: "كسر التحكم بالوصول (IDOR)",
    en: "Broken Object Level Authorization",
    risk: "إرجاع أي سجلّ بناءً على معرّفه فقط — دون التأكد أن المستخدم الحالي يملكه — يتيح لأي شخص رؤية بيانات غيره بمجرد تغيير الرقم في الرابط.",
    vuln: `// ❌ هشّ: نرجّع الفاتورة بالـ ID فقط، بلا تحقق من المالك
app.get("/invoices/:id", authRequired, (req, res) => {
  const invoice = invoices.find(i => i.id === req.params.id);
  if (!invoice) return res.status(404).json({ error: "غير موجودة" });
  res.json(invoice); // أي مستخدم مسجّل يرى فاتورة أي أحد بتغيير الرقم!
});`,
    attack:
      'المستخدم يطلب فاتورته <code>/invoices/1001</code>، ثم يجرّب <code>/invoices/1002</code>، <code>1003</code>… فيقرأ فواتير بقية العملاء. هذه من أكثر ثغرات الـ API انتشارًا.',
    secure: `// ✅ آمن: نتحقق أن المورد يخص المستخدم الحالي (req.user من التوكن)
app.get("/invoices/:id", authRequired, (req, res) => {
  const invoice = invoices.find(i => i.id === req.params.id);
  // نعيد 404 (لا 403) حتى لا نكشف أن الفاتورة موجودة أصلًا
  if (!invoice || invoice.ownerId !== req.user.sub) {
    return res.status(404).json({ error: "غير موجودة" });
  }
  res.json(invoice);
});`,
    lesson:
      "طبّق التحقق من الصلاحية على مستوى كل كائن وفي كل طلب على الخادم. لا تثق برقم المعرّف القادم من العميل، واعتمد هوية المستخدم من التوكن لا من الطلب.",
  },
];

/* ---------- بناء بطاقات المقارنة ---------- */
function buildComparisons() {
  const root = document.getElementById("comparisons");
  if (!root) return;

  comparisons.forEach((c, index) => {
    const card = document.createElement("article");
    card.className = "cmp";

    // الرأس
    const head = document.createElement("div");
    head.className = "cmp__head";
    head.innerHTML = `
      <span class="cmp__badge">${c.owasp}</span>
      <h3 class="cmp__title">${index + 1}. ${c.title} <span class="en">— ${c.en}</span></h3>
      <p class="cmp__risk"><strong>الخطر:</strong> ${c.risk}</p>`;

    // التبويبات
    const tabs = document.createElement("div");
    tabs.className = "cmp__tabs";
    const tabBad = makeTab("الكود الهشّ ❌", "tab--bad", true);
    const tabGood = makeTab("الكود الآمن ✅", "tab--good", false);
    tabs.append(tabBad, tabGood);

    // اللوحات
    const panels = document.createElement("div");
    panels.className = "cmp__panels";

    const panelBad = document.createElement("div");
    panelBad.className = "panel panel--bad is-active";
    panelBad.append(
      flag("❌ الطريقة الخاطئة"),
      codeBlock(c.vuln),
      note("attack", `<strong>🎯 مثال الاستغلال:</strong> ${c.attack}`)
    );

    const panelGood = document.createElement("div");
    panelGood.className = "panel panel--good";
    panelGood.append(
      flag("✅ الطريقة الصحيحة"),
      codeBlock(c.secure),
      note("lesson", `<strong>💡 الدرس المستفاد:</strong> ${c.lesson}`)
    );

    panels.append(panelBad, panelGood);

    // ربط التبويبات
    tabBad.addEventListener("click", () => switchPanel(tabBad, tabGood, panelBad, panelGood));
    tabGood.addEventListener("click", () => switchPanel(tabGood, tabBad, panelGood, panelBad));

    card.append(head, tabs, panels);
    root.append(card);
  });

  // تلوين الكود
  if (window.hljs) document.querySelectorAll("pre code").forEach((el) => window.hljs.highlightElement(el));
}

function makeTab(label, variant, active) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = `tab ${variant}${active ? " is-active" : ""}`;
  b.textContent = label;
  return b;
}

function switchPanel(onTab, offTab, onPanel, offPanel) {
  onTab.classList.add("is-active");
  offTab.classList.remove("is-active");
  onPanel.classList.add("is-active");
  offPanel.classList.remove("is-active");
}

function flag(text) {
  const span = document.createElement("span");
  span.className = "panel__flag";
  span.textContent = text;
  return span;
}

function codeBlock(code) {
  const wrap = document.createElement("div");
  wrap.className = "codeblock";

  const pre = document.createElement("pre");
  const codeEl = document.createElement("code");
  codeEl.className = "language-javascript";
  codeEl.textContent = code; // تهريب تلقائي للرموز
  pre.append(codeEl);

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.textContent = "نسخ";
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code);
      btn.textContent = "تم النسخ ✓";
      setTimeout(() => (btn.textContent = "نسخ"), 1600);
    } catch {
      btn.textContent = "تعذّر النسخ";
    }
  });

  wrap.append(btn, pre);
  return wrap;
}

function note(kind, html) {
  const p = document.createElement("p");
  p.className = `note note--${kind}`;
  p.innerHTML = html;
  return p;
}

/* ---------- الاختبار القصير ---------- */
const quizData = [
  {
    q: "ما الحل الأساسي لمنع حقن SQL؟",
    opts: [
      "تشفير قاعدة البيانات بالكامل",
      "استخدام الاستعلامات المُعامَلة (Parameterized Queries)",
      "إخفاء رسائل الخطأ عن المستخدم",
    ],
    answer: 1,
    why: "القيمة تُمرَّر كبيانات لا كجزء من أمر SQL، فيستحيل تغيير منطق الاستعلام.",
  },
  {
    q: "كيف نخزّن كلمات المرور بشكل آمن؟",
    opts: [
      "كنص صريح مع نسخة احتياطية",
      "بتشفير قابل لفك التشفير",
      "كتجزئة (Hash) عبر bcrypt أو argon2",
    ],
    answer: 2,
    why: "التجزئة في اتجاه واحد؛ حتى لو تسرّبت القاعدة تبقى كلمات المرور محمية.",
  },
  {
    q: "ثغرة IDOR تحدث عندما…",
    opts: [
      "لا نتحقق أن المورد المطلوب يخصّ المستخدم الحالي",
      "نستخدم HTTPS بدل HTTP",
      "تكون كلمة المرور قصيرة",
    ],
    answer: 0,
    why: "لا بد من التحقق من ملكية الكائن على الخادم في كل طلب، لا الاكتفاء بالمصادقة.",
  },
];

function buildQuiz() {
  const root = document.getElementById("quiz");
  if (!root) return;

  quizData.forEach((item, qi) => {
    const q = document.createElement("div");
    q.className = "q";

    const text = document.createElement("p");
    text.className = "q__text";
    text.textContent = `${qi + 1}. ${item.q}`;

    const opts = document.createElement("div");
    opts.className = "q__opts";

    const feedback = document.createElement("p");
    feedback.className = "q__feedback";

    item.opts.forEach((opt, oi) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "q__opt";
      b.textContent = opt;
      b.addEventListener("click", () => {
        const buttons = opts.querySelectorAll(".q__opt");
        buttons.forEach((btn) => (btn.disabled = true));
        if (oi === item.answer) {
          b.classList.add("correct");
          feedback.textContent = "إجابة صحيحة ✓ — " + item.why;
          feedback.classList.add("ok");
        } else {
          b.classList.add("wrong");
          buttons[item.answer].classList.add("correct");
          feedback.classList.remove("ok");
          feedback.textContent = "الإجابة الصحيحة مظلّلة بالأخضر — " + item.why;
        }
      });
      opts.append(b);
    });

    q.append(text, opts, feedback);
    root.append(q);
  });
}

/* ---------- الإقلاع ---------- */
document.addEventListener("DOMContentLoaded", () => {
  buildComparisons();
  buildQuiz();
});
