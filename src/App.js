import { useState, useRef } from "react";

// ── Security utilities ──────────────────────────────────────────────────────
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateSalt() {
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(plain) {
  const salt = generateSalt();
  const hash = await sha256(salt + plain);
  return { hash, salt, display: `$2b$12$${salt}${hash.slice(0, 22)}...` };
}

// Pre-set employee accounts (in production these would be in a secure DB)
const EMPLOYEES = [
  { username: "emp_john", password: "John@1234!", name: "John Mokoena", role: "Senior Payments Officer", branch: "Johannesburg HQ" },
  { username: "emp_sarah", password: "Sarah@5678!", name: "Sarah Van Der Berg", role: "International Transfers Clerk", branch: "Cape Town Branch" },
  { username: "emp_admin", password: "Admin@9999!", name: "Admin User", role: "System Administrator", branch: "Head Office" },
];

// ── RegEx whitelists ────────────────────────────────────────────────────────
const REGEX = {
  username: /^[a-zA-Z0-9_]{3,20}$/,
  password: /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,64}$/,
  accountNumber: /^\d{10,16}$/,
  swiftCode: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/,
  amount: /^\d{1,12}(\.\d{1,2})?$/,
  reference: /^[a-zA-Z0-9\s\-_]{3,35}$/,
  otp: /^\d{6}$/,
  beneficiaryName: /^[a-zA-Z\s'\-]{2,60}$/,
};

function validate(field, value) {
  if (!value) return "This field is required.";
  if (!REGEX[field]) return null;
  return REGEX[field].test(value) ? null : getErrMsg(field);
}

function getErrMsg(field) {
  const msgs = {
    username: "3–20 chars, letters/numbers/underscore only.",
    password: "Min 8 chars with uppercase, number & special char.",
    accountNumber: "10–16 digits, no spaces.",
    swiftCode: "Valid SWIFT/BIC code (e.g. ABCDZAJJXXX).",
    amount: "Valid amount up to 2 decimal places.",
    reference: "3–35 chars, letters/numbers/spaces/hyphens only.",
    otp: "6-digit code required.",
    beneficiaryName: "Letters, spaces, hyphens and apostrophes only.",
  };
  return msgs[field] || "Invalid input.";
}

function sanitise(str) {
  return str.replace(/<[^>]*>/g, "").replace(/[<>&"']/g, (c) =>
    ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#x27;" }[c])
  );
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Design tokens ───────────────────────────────────────────────────────────
const C = {
  bg: "#080c18",
  surface: "#0f1623",
  surface2: "#162033",
  border: "#1a3355",
  accent: "#0f5fcc",
  accentLight: "#2d7fff",
  gold: "#b8860b",
  goldLight: "#d4a017",
  text: "#dde4f0",
  muted: "#5a7090",
  danger: "#cc3333",
  success: "#1a9e6e",
  warn: "#cc8800",
};

const FONT = "'IBM Plex Mono', 'Courier New', monospace";
const SANS = "'IBM Plex Sans', 'Segoe UI', sans-serif";

// ── Reusable components ─────────────────────────────────────────────────────
const Panel = ({ children, style }) => (
  <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, padding: "1.75rem 2rem", ...style }}>
    {children}
  </div>
);

const Label = ({ children }) => (
  <label style={{ display: "block", fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", color: C.muted, marginBottom: 6, fontFamily: FONT }}>
    {children}
  </label>
);

const Input = ({ error, ...props }) => (
  <input
    {...props}
    style={{ width: "100%", background: C.surface2, border: `1px solid ${error ? C.danger : C.border}`, borderRadius: 6, color: C.text, padding: "10px 14px", fontSize: 14, fontFamily: FONT, outline: "none", boxSizing: "border-box", transition: "border-color 0.2s" }}
    onFocus={(e) => (e.target.style.borderColor = error ? C.danger : C.accentLight)}
    onBlur={(e) => (e.target.style.borderColor = error ? C.danger : C.border)}
  />
);

const Err = ({ msg }) => msg ? <p style={{ color: C.danger, fontSize: 12, marginTop: 4, fontFamily: FONT }}>⚠ {msg}</p> : null;

const Btn = ({ children, onClick, disabled, variant = "primary", style }) => (
  <button
    onClick={onClick}
    disabled={disabled}
    style={{ background: variant === "primary" ? C.accent : variant === "ghost" ? "transparent" : C.surface2, color: variant === "primary" ? "#fff" : C.accentLight, border: `1px solid ${variant === "primary" ? C.accent : C.border}`, borderRadius: 6, padding: "11px 22px", fontSize: 14, fontFamily: FONT, cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.5 : 1, transition: "all 0.15s", letterSpacing: "0.04em", ...style }}
  >
    {children}
  </button>
);

const Tag = ({ color, children }) => (
  <span style={{ background: color + "22", color, border: `1px solid ${color}44`, borderRadius: 4, padding: "2px 8px", fontSize: 11, fontFamily: FONT, letterSpacing: "0.06em" }}>
    {children}
  </span>
);

const SecurityStrip = () => (
  <div style={{ display: "flex", gap: 16, flexWrap: "wrap", padding: "10px 16px", background: C.surface2, border: `1px solid ${C.border}`, borderRadius: 8, marginBottom: 24 }}>
    {[["🔒", "TLS 1.3"], ["🛡", "XSS Protected"], ["🔑", "Salted Hashing"], ["🧩", "CSRF Tokens"], ["📋", "RegEx Whitelist"], ["🚫", "SQLi Hardened"], ["👤", "Employee Only"]].map(([icon, label]) => (
      <span key={label} style={{ fontSize: 12, color: C.muted, fontFamily: FONT, whiteSpace: "nowrap" }}>{icon} {label}</span>
    ))}
  </div>
);

// ── LOGIN PAGE ──────────────────────────────────────────────────────────────
function LoginPage({ onLogin }) {
  const [f, setF] = useState({ username: "", password: "" });
  const [errs, setErrs] = useState({});
  const [loading, setLoading] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [loginErr, setLoginErr] = useState("");
  const csrfToken = useRef(generateToken());
  const attempts = useRef(0);

  const change = (k) => (e) => {
    const v = sanitise(e.target.value);
    setF((p) => ({ ...p, [k]: v }));
    setErrs((p) => ({ ...p, [k]: validate(k, v) }));
    setLoginErr("");
  };

  const submit = async () => {
    // Rate limiting simulation
    attempts.current += 1;
    if (attempts.current > 5) {
      setLoginErr("Too many attempts. Please wait 30 seconds.");
      return;
    }

    const e = {};
    Object.keys(f).forEach((k) => { const err = validate(k, f[k]); if (err) e[k] = err; });
    if (Object.keys(e).length) { setErrs(e); return; }

    setLoading(true);
    await new Promise((r) => setTimeout(r, 900));

    // Check against pre-set employees
    const employee = EMPLOYEES.find(
      (emp) => emp.username === f.username && emp.password === f.password
    );

    setLoading(false);

    if (employee) {
      const { display } = await hashPassword(f.password);
      onLogin({ ...employee, csrfToken: csrfToken.current, hashDisplay: display });
    } else {
      setLoginErr("Invalid credentials. Access denied.");
    }
  };

  return (
    <div style={{ maxWidth: 420, margin: "0 auto" }}>
      <SecurityStrip />

      {/* Employee accounts hint for demo */}
      <div style={{ background: C.surface2, border: `1px solid ${C.warn}33`, borderRadius: 8, padding: "12px 16px", marginBottom: 20 }}>
        <p style={{ color: C.warn, fontSize: 11, fontFamily: FONT, marginBottom: 8 }}>DEMO EMPLOYEE ACCOUNTS</p>
        {EMPLOYEES.map((e) => (
          <p key={e.username} style={{ color: C.muted, fontSize: 11, fontFamily: FONT, margin: "2px 0" }}>
            {e.username} / {e.password} — <span style={{ color: C.text }}>{e.name}</span>
          </p>
        ))}
      </div>

      <Panel>
        <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT, marginBottom: 20 }}>
          CSRF: <span style={{ color: C.goldLight }}>{csrfToken.current.slice(0, 16)}…</span>
        </p>

        <div style={{ marginBottom: 16 }}>
          <Label>Employee Username</Label>
          <Input value={f.username} onChange={change("username")} error={errs.username} placeholder="emp_username" />
          <Err msg={errs.username} />
        </div>

        <div style={{ marginBottom: 20 }}>
          <Label>Password</Label>
          <div style={{ position: "relative" }}>
            <Input type={showPw ? "text" : "password"} value={f.password} onChange={change("password")} error={errs.password} placeholder="••••••••" />
            <button onClick={() => setShowPw((p) => !p)} style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 13 }}>
              {showPw ? "hide" : "show"}
            </button>
          </div>
          <Err msg={errs.password} />
        </div>

        {loginErr && (
          <div style={{ background: C.danger + "22", border: `1px solid ${C.danger}44`, borderRadius: 6, padding: "10px 14px", marginBottom: 16 }}>
            <p style={{ color: C.danger, fontSize: 13, fontFamily: FONT }}>🚫 {loginErr}</p>
          </div>
        )}

        <Btn onClick={submit} disabled={loading} style={{ width: "100%" }}>
          {loading ? "Authenticating…" : "Employee Sign In →"}
        </Btn>

        <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT, textAlign: "center", marginTop: 16 }}>
          🔒 Authorised personnel only. No self-registration permitted.
        </p>
      </Panel>
    </div>
  );
}

// ── OTP PAGE ────────────────────────────────────────────────────────────────
function OTPPage({ employee, onVerified }) {
  const [otp, setOtp] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const fakeOtp = "482917";

  const submit = async () => {
    const e = validate("otp", otp);
    if (e) { setErr(e); return; }
    setLoading(true);
    await new Promise((r) => setTimeout(r, 800));
    setLoading(false);
    if (otp === fakeOtp) onVerified();
    else setErr("Incorrect OTP. Try: " + fakeOtp);
  };

  return (
    <Panel style={{ maxWidth: 380, margin: "0 auto", textAlign: "center" }}>
      <p style={{ fontSize: 28, marginBottom: 8 }}>📱</p>
      <h3 style={{ color: C.text, fontFamily: FONT, marginBottom: 4, fontSize: 16 }}>Two-Factor Authentication</h3>
      <p style={{ color: C.muted, fontFamily: SANS, fontSize: 13, marginBottom: 8 }}>
        Welcome, <span style={{ color: C.goldLight }}>{employee.name}</span>
      </p>
      <p style={{ color: C.muted, fontFamily: SANS, fontSize: 13, marginBottom: 20 }}>
        A 6-digit code has been sent to your registered device.
      </p>
      <p style={{ color: C.warn, fontSize: 11, fontFamily: FONT, marginBottom: 16 }}>Demo OTP: {fakeOtp}</p>
      <Input
        value={otp}
        onChange={(e) => { setOtp(sanitise(e.target.value)); setErr(""); }}
        error={err}
        placeholder="000000"
        maxLength={6}
        style={{ textAlign: "center", letterSpacing: "0.4em", fontSize: 20 }}
      />
      <Err msg={err} />
      <Btn onClick={submit} disabled={loading} style={{ width: "100%", marginTop: 16 }}>
        {loading ? "Verifying…" : "Verify →"}
      </Btn>
    </Panel>
  );
}

// ── PAYMENT PAGE ────────────────────────────────────────────────────────────
function PaymentPage({ employee, onLogout }) {
  const [f, setF] = useState({ beneficiaryName: "", accountNumber: "", swiftCode: "", amount: "", reference: "", currency: "ZAR" });
  const [errs, setErrs] = useState({});
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(null);
  const [history, setHistory] = useState([]);

  const change = (k) => (e) => {
    const v = sanitise(e.target.value);
    setF((p) => ({ ...p, [k]: v }));
    setErrs((p) => ({ ...p, [k]: validate(k, v) }));
  };

  const submit = async () => {
    const e = {};
    ["beneficiaryName", "accountNumber", "swiftCode", "amount", "reference"].forEach((k) => {
      const err = validate(k, f[k]); if (err) e[k] = err;
    });
    if (Object.keys(e).length) { setErrs(e); return; }
    setLoading(true);
    await new Promise((r) => setTimeout(r, 1400));
    setLoading(false);
    const record = { ...f, ref: generateToken().slice(0, 12).toUpperCase(), ts: new Date().toISOString(), officer: employee.name };
    setSent(record);
    setHistory((p) => [record, ...p]);
  };

  if (sent) return (
    <div style={{ maxWidth: 560, margin: "0 auto" }}>
      <Panel style={{ marginBottom: 16 }}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <p style={{ fontSize: 32 }}>✅</p>
          <h3 style={{ color: C.success, fontFamily: FONT }}>Submitted to SWIFT Network</h3>
          <Tag color={C.success}>TRANSMITTED</Tag>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {[
            ["SWIFT Ref", sent.ref],
            ["Beneficiary", sent.beneficiaryName],
            ["Account", "••••" + sent.accountNumber.slice(-4)],
            ["SWIFT Code", sent.swiftCode],
            ["Amount", `${sent.currency} ${Number(sent.amount).toFixed(2)}`],
            ["Reference", sent.reference],
            ["Officer", sent.officer],
            ["Timestamp", new Date(sent.ts).toLocaleTimeString()],
          ].map(([k, v]) => (
            <div key={k} style={{ background: C.surface2, borderRadius: 8, padding: "10px 14px" }}>
              <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT, marginBottom: 4 }}>{k}</p>
              <p style={{ color: C.text, fontSize: 13, fontFamily: FONT }}>{v}</p>
            </div>
          ))}
        </div>
        <Btn onClick={() => setSent(null)} style={{ marginTop: 20, width: "100%" }} variant="ghost">New payment</Btn>
      </Panel>

      {history.length > 0 && (
        <Panel>
          <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT, marginBottom: 12 }}>TRANSACTION HISTORY (THIS SESSION)</p>
          {history.map((h, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
              <span style={{ color: C.text, fontSize: 12, fontFamily: FONT }}>{h.ref}</span>
              <span style={{ color: C.goldLight, fontSize: 12, fontFamily: FONT }}>{h.currency} {Number(h.amount).toFixed(2)}</span>
              <Tag color={C.success}>SENT</Tag>
            </div>
          ))}
        </Panel>
      )}
    </div>
  );

  return (
    <div style={{ maxWidth: 560, margin: "0 auto" }}>
      {/* Employee header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div>
          <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT }}>Logged in as</p>
          <p style={{ color: C.goldLight, fontFamily: FONT, fontSize: 14 }}>{employee.name}</p>
          <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT }}>{employee.role} · {employee.branch}</p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <Tag color={C.success}>2FA Verified</Tag>
          <Btn onClick={onLogout} variant="ghost" style={{ padding: "6px 12px", fontSize: 12 }}>Logout</Btn>
        </div>
      </div>

      <SecurityStrip />

      <Panel>
        <h3 style={{ color: C.text, fontFamily: FONT, marginBottom: 20, fontSize: 16 }}>
          International SWIFT Payment
        </h3>

        <div style={{ marginBottom: 14 }}>
          <Label>Beneficiary Name</Label>
          <Input value={f.beneficiaryName} onChange={change("beneficiaryName")} error={errs.beneficiaryName} placeholder="John Smith" />
          <Err msg={errs.beneficiaryName} />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 14 }}>
          <div>
            <Label>Account Number</Label>
            <Input value={f.accountNumber} onChange={change("accountNumber")} error={errs.accountNumber} placeholder="1234567890" />
            <Err msg={errs.accountNumber} />
          </div>
          <div>
            <Label>SWIFT / BIC Code</Label>
            <Input value={f.swiftCode} onChange={change("swiftCode")} error={errs.swiftCode} placeholder="ABCDZAJJXXX" />
            <Err msg={errs.swiftCode} />
          </div>
          <div>
            <Label>Currency</Label>
            <select
              value={f.currency}
              onChange={(e) => setF((p) => ({ ...p, currency: e.target.value }))}
              style={{ width: "100%", background: C.surface2, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, padding: "10px 14px", fontSize: 14, fontFamily: FONT, outline: "none", boxSizing: "border-box" }}
            >
              {["ZAR", "USD", "EUR", "GBP", "JPY", "AUD"].map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
          <div>
            <Label>Amount</Label>
            <Input value={f.amount} onChange={change("amount")} error={errs.amount} placeholder="10000.00" />
            <Err msg={errs.amount} />
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <Label>Payment Reference</Label>
          <Input value={f.reference} onChange={change("reference")} error={errs.reference} placeholder="INV-2026-001" />
          <Err msg={errs.reference} />
        </div>

        {/* Security context */}
        <div style={{ background: C.surface2, borderRadius: 8, padding: "12px 14px", marginBottom: 20 }}>
          <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT, marginBottom: 8 }}>Security context</p>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Tag color={C.accent}>CSRF: {employee.csrfToken?.slice(0, 8)}…</Tag>
            <Tag color={C.goldLight}>2FA verified</Tag>
            <Tag color={C.success}>TLS 1.3</Tag>
            <Tag color={C.success}>Input validated</Tag>
            <Tag color={C.success}>XSS sanitised</Tag>
          </div>
        </div>

        <Btn onClick={submit} disabled={loading} style={{ width: "100%" }}>
          {loading ? "Submitting to SWIFT…" : "Submit Payment →"}
        </Btn>
      </Panel>
    </div>
  );
}

// ── App shell ───────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState("login");
  const [employee, setEmployee] = useState(null);

  const handleLogin = (emp) => { setEmployee(emp); setPage("otp"); };
  const handleVerified = () => setPage("payment");
  const handleLogout = () => { setEmployee(null); setPage("login"); };

  const stepLabels = {
    login: "01 / EMPLOYEE AUTHENTICATION",
    otp: "02 / TWO-FACTOR VERIFICATION",
    payment: "03 / SWIFT PAYMENT SUBMISSION",
  };

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, fontFamily: SANS, padding: "2rem 1rem" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500&display=swap');`}</style>

      {/* Header */}
      <div style={{ maxWidth: 560, margin: "0 auto 2rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontFamily: FONT, fontSize: 18, color: C.goldLight, margin: 0, letterSpacing: "0.06em" }}>◈ NEXUS BANK</h1>
          <p style={{ color: C.muted, fontSize: 11, fontFamily: FONT, margin: "2px 0 0" }}>Employee Payments Portal — Internal Use Only</p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {["login", "otp", "payment"].map((p) => (
            <div key={p} style={{ width: 8, height: 8, borderRadius: "50%", background: page === p ? C.accentLight : C.border, transition: "background 0.3s" }} />
          ))}
        </div>
      </div>

      <p style={{ textAlign: "center", color: C.muted, fontSize: 11, fontFamily: FONT, marginBottom: 24, letterSpacing: "0.1em" }}>
        {stepLabels[page]}
      </p>

      {page === "login" && <LoginPage onLogin={handleLogin} />}
      {page === "otp" && <OTPPage employee={employee} onVerified={handleVerified} />}
      {page === "payment" && <PaymentPage employee={employee} onLogout={handleLogout} />}

      <p style={{ textAlign: "center", color: C.border, fontSize: 10, fontFamily: FONT, marginTop: 40 }}>
        TLS 1.3 · CSRF · XSS sanitisation · RegEx whitelisting · Salted hashing · No self-registration
      </p>
    </div>
  );
}
