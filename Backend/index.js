const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Handlebars = require("handlebars");
// dynamic import for node-fetch in CommonJS
const fetchDynamic = (...args) => import("node-fetch").then(m => m.default(...args));
require("dotenv").config();

const data = require("./data.js");
const config = require("./config.json");
const app = express();

// Security & parsing
app.set("trust proxy", 1);
app.use(helmet());
app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001"],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
  })
);
app.use(express.json({ limit: "1mb" }));
// Basic rate limiter for auth endpoints
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

// Ensure reports directory exists and is served statically
const reportsDir = path.join(__dirname, "reports");
if (!fs.existsSync(reportsDir)) {
  fs.mkdirSync(reportsDir, { recursive: true });
}
app.use("/reports", express.static(reportsDir));

// Simple file-based user persistence (replace with a real DB in production)
const usersFile = path.join(__dirname, "users.json");
function readUsers() {
  try {
    if (!fs.existsSync(usersFile)) return [];
    const raw = fs.readFileSync(usersFile, "utf8");
    return JSON.parse(raw || "[]");
  } catch (e) {
    console.error("Failed to read users.json:", e);
    return [];
  }
}
function writeUsers(users) {
  try {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), "utf8");
  } catch (e) {
    console.error("Failed to write users.json:", e);
  }
}

const JWT_SECRET = process.env.JWT_SECRET || "change_me_in_env";
const PORT = Number(process.env.PORT || 5000);

// ---------- Config-driven data loading ----------
function interpolate(str = "", vars = {}) {
  return String(str).replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, k) => (vars[k] != null ? vars[k] : ""));
}

async function loadSessionData(session_id, assessmentId, reportConf) {
  const ds = reportConf && reportConf.dataSource ? reportConf.dataSource : { type: "local" };
  const vars = { session_id, assessment_id: assessmentId, PORT };
  if (ds.type === "local") {
    // back-compat: use bundled data.js array
    return data.find((d) => d.session_id === session_id || d.sessionid === session_id) || null;
  }
  if (ds.type === "file") {
    try {
      const filePath = path.resolve(__dirname, interpolate(ds.path, vars));
      const raw = fs.readFileSync(filePath, "utf8");
      return JSON.parse(raw);
    } catch (e) {
      console.error("File dataSource error:", e);
      return null;
    }
  }
  if (ds.type === "http") {
    try {
      const url = interpolate(ds.url, vars);
      const headers = {};
      if (ds.headers) {
        for (const [k, v] of Object.entries(ds.headers)) headers[k] = interpolate(v, { ...vars, env: process.env });
      }
      const resp = await fetchDynamic(url, { headers });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      console.error("HTTP dataSource error:", e);
      return null;
    }
  }
  // Unknown type
  return null;
}

// Signup route
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }
    if (String(username).length < 3) {
      return res.status(400).json({ error: "Username must be at least 3 characters" });
    }
    // Basic password policy
    if (String(password).length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: "Password must be >=8 chars and include letters and numbers" });
    }
    const users = readUsers();
    if (users.find((u) => u.username.toLowerCase() === String(username).toLowerCase())) {
      return res.status(400).json({ error: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    users.push({ username, password: hashedPassword, createdAt: new Date().toISOString() });
    writeUsers(users);
    res.json({ message: "User registered" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login route
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const users = readUsers();
    const user = users.find((u) => u.username === username);
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// JWT authentication middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });
  const token = authHeader.split(" ")[1];
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Utility: resolve a flexible path with simple array filter support, e.g. "exercises[id=235].setList[0].time"
function resolvePath(obj, expr) {
  if (!expr || !obj) return undefined;
  // split by dots but keep bracketed parts
  const parts = expr.split('.');
  let current = obj;
  for (let raw of parts) {
    if (current == null) return undefined;
    // handle filters like name[id=235]
    const filterMatch = raw.match(/^([a-zA-Z0-9_]+)\[(.+)\]$/);
    if (filterMatch) {
      const prop = filterMatch[1];
      const clause = filterMatch[2]; // e.g. id=235 or 0
      current = current[prop];
      if (Array.isArray(current)) {
        // index access like [0]
        const indexOnly = clause.match(/^(\d+)$/);
        if (indexOnly) {
          current = current[Number(indexOnly[1])];
          continue;
        }
        // key=value filter
        const kv = clause.match(/^([a-zA-Z0-9_]+)=(.+)$/);
        if (kv) {
          const key = kv[1];
          let val = kv[2];
          // strip quotes if present
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          // try number
          const num = Number(val);
          const target = isNaN(num) ? val : num;
          current = current.find((it) => (it && it[key]) === target);
          continue;
        }
      }
      // if not array, undefined
      return undefined;
    }
    // bracket index like setList[0]
    const indexMatch = raw.match(/^([a-zA-Z0-9_]+)\[(\d+)\]$/);
    if (indexMatch) {
      const prop = indexMatch[1];
      const idx = Number(indexMatch[2]);
      current = current[prop];
      if (!Array.isArray(current)) return undefined;
      current = current[idx];
      continue;
    }
    // plain property
    current = current[raw];
  }
  return current;
}

function formatValue(value, format) {
  if (value == null) return "-";
  if (!format) return String(value);
  if (format === "percent") return `${Number(value).toFixed(0)}%`;
  if (format === "number") return `${Number(value)}`;
  return String(value);
}

function classifyValue(value, rules = []) {
  const num = Number(value);
  if (isNaN(num)) return undefined;
  for (const r of rules) {
    const gt = r.gt != null ? num > r.gt : true;
    const gte = r.gte != null ? num >= r.gte : true;
    const lt = r.lt != null ? num < r.lt : true;
    const lte = r.lte != null ? num <= r.lte : true;
    if ((r.gt != null ? gt : gte) && (r.lt != null ? lt : lte)) {
      return r.label;
    }
  }
  return undefined;
}

function buildHtml(sessionData, reportType, reportConf) {
  let html = `
    <style>
      body { font-family: Arial, sans-serif; margin: 20px; }
      h1 { color: #2E86C1; }
      h2 { color: #117A65; margin-top: 20px; }
      ul { list-style-type: none; padding: 0; }
      li { background: #D6EAF8; margin: 5px 0; padding: 8px; border-radius: 4px; }
      .small { color: #555; font-size: 12px; }
    </style>
    <body>
      <h1>Assessment Report - ${reportType}</h1>`;
  for (const [sectionName, fields] of Object.entries(reportConf.sections)) {
    html += `<h2>${sectionName}</h2><ul>`;
    for (const [label, mapping] of Object.entries(fields)) {
      let value;
      let format;
      let classification;
      if (typeof mapping === "string") {
        value = resolvePath(sessionData, mapping);
      } else if (typeof mapping === "object" && mapping) {
        value = resolvePath(sessionData, mapping.path);
        format = mapping.format;
        if (mapping.classify) {
          classification = classifyValue(value, mapping.classify);
        }
      }
      const display = formatValue(value, format);
      html += `<li>${label}: ${display}${classification ? ` <span class="small">(${classification})</span>` : ""}</li>`;
    }
    html += "</ul>";
  }
  html += `</body>`;
  return html;
}

// Protected generate-report routes (POST and GET). Accepts body.session_id or query.session_id
async function handleGenerate(req, res) {
  try {
    const rawSession = req.body.session_id || req.body.sessionid || req.query.session_id || req.query.sessionid;
    let session_id = rawSession != null ? String(rawSession).trim() : undefined;
    if (!session_id) return res.status(400).json({ error: "session_id is required" });

    // Normalize: replace spaces/dashes with underscores for user convenience
    session_id = session_id.replace(/\s+/g, "_").replace(/-/g, "_");

    // Removed temporary session_003 alias

    // helper: robust local finder (trim/case-insensitive)
    const findLocal = (sid) => {
      if (!sid) return null;
      const needle = String(sid).trim().toLowerCase();
      return (
        data.find((d) =>
          (d.session_id && String(d.session_id).trim().toLowerCase() === needle) ||
          (d.sessionid && String(d.sessionid).trim().toLowerCase() === needle)
        ) || null
      );
    };

    // Load session data using configured dataSource (defaults to local)
    // First, try to discover assessment id using local data as a fallback if needed
    let sessionData = findLocal(session_id);
    let reportType = sessionData && (sessionData.assessment_id || sessionData.assessmentid);
    // If not found locally, attempt to load via config by iterating known assessment keys
    if (!reportType) {
      // Try each assessment key's data source to load the session
      for (const assessmentKey of Object.keys(config)) {
        const temp = await loadSessionData(session_id, assessmentKey, config[assessmentKey]);
        if (temp) {
          sessionData = temp;
          reportType = assessmentKey;
          break;
        }
      }
    } else {
      // We know assessment; prefer configured data source
      const conf = config[reportType];
      const loaded = await loadSessionData(session_id, reportType, conf || {});
      if (loaded) sessionData = loaded;
    }

    if (!sessionData) {
      console.warn("Session not found:", session_id);
      return res.status(404).json({ error: "Session not found" });
    }

    // If still not resolved, deduce reportType from data
    if (!reportType) reportType = sessionData.assessment_id || sessionData.assessmentid;
    const reportConf = config[reportType];
    if (!reportConf) return res.status(400).json({ error: "Unknown report type" });

    // If a template is configured, render via Handlebars; otherwise use legacy buildHtml
    let html;
    if (reportConf.template) {
      // Build a normalized model for the template
      const sections = [];
      for (const [sectionName, fields] of Object.entries(reportConf.sections)) {
        const items = [];
        for (const [label, mapping] of Object.entries(fields)) {
          let value;
          let format;
          let classification;
          if (typeof mapping === "string") {
            value = resolvePath(sessionData, mapping);
          } else if (typeof mapping === "object" && mapping) {
            value = resolvePath(sessionData, mapping.path);
            format = mapping.format;
            if (mapping.classify) {
              classification = classifyValue(value, mapping.classify);
            }
          }
          const display = formatValue(value, format);
          const missing = (value === undefined || value === null);
          items.push({ label, value, display, classification, missing });
        }
        sections.push({ name: sectionName, items });
      }
      const templatePath = path.join(__dirname, "templates", reportConf.template);
      const templateSrc = fs.readFileSync(templatePath, "utf8");
      const template = Handlebars.compile(templateSrc);
      html = template({ reportType, sections, session: sessionData });
    } else {
      html = buildHtml(sessionData, reportType, reportConf);
    }

    const pdfFilename = `report_${session_id}.pdf`;
    const pdfPath = path.join(reportsDir, pdfFilename);
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });
    await page.pdf({ path: pdfPath, format: "A4" });
    await browser.close();

    // Return a URL that frontend can open
    const fileUrl = `/reports/${pdfFilename}`;
    res.json({ success: true, file: fileUrl });
  } catch (err) {
    console.error("Generate report error:", err);
    res.status(500).json({ error: "Failed to generate report" });
  }
}

app.post("/generate-report", authMiddleware, handleGenerate);
app.get("/generate-report", authMiddleware, handleGenerate);

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
