/* AndroGuard site: landing + free trial, accounts, scan reports and the admin CRM.
   ponytail: React 18 from a CDN with htm templates and hash routing, no build step. Move to Vite once it outgrows one file. */
const {useState, useEffect, useRef, useCallback, createContext, useContext} = React;
const html = htm.bind(React.createElement);
const Ctx = createContext({me: null, refresh: () => {}});
const FREE = 3, SIGNUP_LIMIT = 20;  // mirror FREE_SCANS and DEFAULT_USER_LIMIT in app/api.py

async function api(path, {json, ...opts} = {}) {
  const res = await fetch(path, json ? {...opts, headers: {"Content-Type": "application/json"}, body: JSON.stringify(json)} : opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(typeof data.detail === "string" ? data.detail : "Something went wrong. Please try again."), {status: res.status});
  return data;
}
const go = path => { location.hash = path; };
const active = s => s.status === "queued" || s.status === "running";
const isAdmin = u => u && (u.role === "admin" || u.role === "superadmin");
const date = iso => iso ? new Date(iso).toLocaleString([], {dateStyle: "medium", timeStyle: "short"}) : "";
const title = s => s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : "";
const Icon = ({n}) => html`<i className=${"ph ph-" + n} aria-hidden="true"></i>`;
const Chip = ({v}) => html`<span className=${"chip " + String(v || "").toLowerCase()}>${title(v)}</span>`;
const Skeleton = ({rows = 3}) => html`<div style=${{display: "grid", gap: "12px"}} aria-busy="true" aria-label="Loading">
  ${Array.from({length: rows}, (_, i) => html`<div key=${i} className="skeleton" style=${{height: "56px"}}></div>`)}</div>`;
const scrollToId = id => document.getElementById(id)?.scrollIntoView({behavior: "smooth"});

function useRoute() {
  const read = () => location.hash.replace(/^#/, "") || "/";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => { setRoute(read()); window.scrollTo(0, 0); };
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return route;
}

function useLoad(path, poll) {  // fetch + optional polling while poll(data) is true
  const [data, setData] = useState(null), [err, setErr] = useState("");
  const load = useCallback(() => api(path).then(d => { setData(d); setErr(""); return d; }).catch(e => setErr(e.message)), [path]);
  useEffect(() => {
    let timer, live = true;
    const tick = () => load().then(d => { if (live && d && poll && poll(d)) timer = setTimeout(tick, 2500); });
    tick();
    return () => { live = false; clearTimeout(timer); };
  }, [load]);
  return [data, err, load, setData];
}

function App() {
  const route = useRoute();
  const [me, setMe] = useState(null);
  const refresh = useCallback(() => api("/api/auth/me").then(setMe).catch(() => setMe({user: null, quota: null})), []);
  useEffect(() => { refresh(); }, [route, refresh]);
  const [, base, arg] = route.split("/");
  const page = base === "" ? html`<${Landing} />`
    : base === "signin" || base === "signup" ? html`<${Auth} signup=${base === "signup"} />`
    : base === "scans" && arg ? html`<${ScanPage} key=${arg} id=${arg} />`
    : base === "scans" ? html`<${MyScans} />`
    : base === "admin" ? html`<${Admin} tab=${arg || "overview"} />`
    : html`<main className="page wrap"><h1>Page not found</h1><p className="muted" style=${{marginTop: "8px"}}><a href="#/">Back to the start</a></p></main>`;
  return html`<${Ctx.Provider} value=${{me, refresh}}><${Nav} base=${base} />${page}<${Footer} /></${Ctx.Provider}>`;
}

function Nav({base}) {
  const {me, refresh} = useContext(Ctx);
  const user = me && me.user, used = me && me.quota && me.quota.used;
  const signOut = async () => { await api("/api/auth/logout", {method: "POST"}); await refresh(); go("/"); };
  const scanNow = () => { go("/"); setTimeout(() => document.getElementById("dropzone")?.focus(), 60); };
  return html`<header className="nav"><div className="wrap nav-row">
    <a className="brand" href="#/" aria-label="AndroGuard home"><${Icon} n="shield-check" /><span className="brand-name">AndroGuard</span></a>
    <nav className="nav-links" aria-label="Main">
      ${base === "" && html`<button className="link hide-sm" onClick=${() => scrollToId("how")}>How it works</button>
        <button className="link hide-sm" onClick=${() => scrollToId("checks")}>What it checks</button>`}
      ${(user || used > 0) && html`<a className="link" href="#/scans">My scans</a>`}
      ${isAdmin(user) && html`<a className="link" href="#/admin">Admin</a>`}
      ${user ? html`<span className="avatar" title=${user.email}>${(user.name || user.email)[0].toUpperCase()}</span>
          <button className="btn ghost sm" onClick=${signOut}>Sign out</button>`
        : html`<a className="link" href="#/signin">Sign in</a><button className="btn primary sm" onClick=${scanNow}>Start free scan</button>`}
    </nav></div></header>`;
}

/* ---------------- landing ---------------- */
function Landing() {
  return html`<main>
    <section className="hero-bg"><${Grid} />
      <div className="hero wrap">
        <div>
          <h1 className="reveal">Find the security holes in your Android app.</h1>
          <p className="lead reveal" style=${{"--d": ".08s"}}>Upload an APK or AAB. Get evidence-backed findings, ranked by real exploitability and mapped to OWASP MASVS.</p>
          <div className="reveal" style=${{"--d": ".16s"}}><${Dropzone} /></div>
        </div>
        <div className="reveal" style=${{"--d": ".24s"}}><${Sample} /></div>
      </div>
    </section>
    <${How} /><${Checks} /><${Privacy} /><${Why} /><${Demo} /><${FinalCta} />
  </main>`;
}

// Animated grid behind the hero: cells light up at random and jump to a new cell while invisible.
const CELL = 48;  // same as background-size of .grid
const place = el => {
  const {clientWidth: w, clientHeight: h} = el.parentNode;
  el.style.left = `${Math.floor(Math.random() * (w / CELL)) * CELL + 1}px`;
  el.style.top = `${Math.floor(Math.random() * (h / CELL)) * CELL + 1}px`;
};
const Grid = () => html`<div className="grid" aria-hidden="true">${Array.from({length: 18}, (_, i) =>
  html`<i key=${i} ref=${el => el && !el.style.left && place(el)} style=${{animationDelay: `${i * 0.4}s`}} onAnimationIteration=${e => place(e.currentTarget)}></i>`)}</div>`;

function Dropzone() {
  const {me, refresh} = useContext(Ctx);
  const input = useRef(null);
  const [drag, setDrag] = useState(false), [busy, setBusy] = useState(false), [err, setErr] = useState(null);
  const user = me && me.user, q = me && me.quota;
  const left = q && q.limit != null ? Math.max(q.limit - q.used, 0) : null;
  if (left === 0) return html`<div className="drop locked"><${Icon} n="lock-key" />
    <div><strong>${user ? "Scan limit reached" : "Free scans used"}</strong>
      <span className="muted">${user ? "Ask the administrator to raise it." : "Create an account to keep going."}</span></div>
    ${!user && html`<a className="btn primary" href="#/signup">Create account</a>`}</div>`;
  const note = !q ? "Checking your free scans" : left == null ? "Unlimited scans on your account"
    : user ? `${left} of ${q.limit} scans left on your account` : `${left} of ${FREE} free scans left, no account needed`;
  const send = async file => {
    if (!file || busy) return;
    if (!/\.(apk|aab)$/i.test(file.name)) return setErr({msg: "Choose an .apk or .aab file."});
    const body = new FormData();
    body.append("file", file);
    setBusy(true); setErr(null);
    try { const {id} = await api("/api/scans", {method: "POST", body}); await refresh(); go(`/scans/${id}`); }
    catch (e) { setErr({msg: e.message, signup: e.status === 403 && !user}); }
    finally { setBusy(false); if (input.current) input.current.value = ""; }
  };
  const open = () => !busy && input.current.click();
  return html`<div>
    <div id="dropzone" tabIndex="0" role="button" aria-label="Choose an APK or AAB file to scan" aria-busy=${busy}
      className=${"drop" + (drag ? " drag" : "")} onClick=${open}
      onKeyDown=${e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } }}
      onDragOver=${e => { e.preventDefault(); setDrag(true); }} onDragLeave=${() => setDrag(false)}
      onDrop=${e => { e.preventDefault(); setDrag(false); send(e.dataTransfer.files[0]); }}>
      <input ref=${input} type="file" accept=".apk,.aab" hidden onChange=${e => send(e.target.files[0])} />
      <${Icon} n=${busy ? "hourglass-medium" : "upload-simple"} />
      <div><strong>${busy ? "Uploading your app" : "Drop your APK or AAB here"}</strong><span className="muted">${busy ? "Keep this tab open" : note}</span></div>
      <span className="btn primary">${user ? "Start scan" : "Start free scan"}</span>
    </div>
    ${err && html`<p className="form-error" role="alert">${err.msg} ${err.signup && html`<a href="#/signup">Create account</a>`}</p>`}
  </div>`;
}

const SAMPLE_ROWS = [  // real output of our scanner for InsecureBankv2
  ["HIGH", "Exported component without permission protection", "TrackUserContentProvider", "72.0"],
  ["HIGH", "Hardcoded cryptographic key", "CryptoClass.java", "61.6"],
  ["HIGH", "World-readable/writable file mode", "MyBroadCastReceiver.java", "59.0"],
  ["MEDIUM", "Exported component without permission protection", "DoTransfer", "49.5"],
];
function Sample() {
  return html`<figure className="preview">
    <div className="preview-card">
      <div className="preview-head"><div><span className="mono small muted">InsecureBankv2.apk</span>
        <div className="preview-risk"><${Chip} v="HIGH" />App risk 72/100</div></div><span className="muted" title="PDF report"><${Icon} n="file-pdf" /></span></div>
      <dl className="stats"><div><dt>Findings</dt><dd>23</dd></div><div><dt>Highly exploitable</dt><dd>15</dd></div><div><dt>In attack chains</dt><dd>8</dd></div></dl>
      <ul className="rows">${SAMPLE_ROWS.map(([sev, t, c, s]) => html`<li key=${t + c}><${Chip} v=${sev} /><span className="t">${t}<span className="c mono">${c}</span></span><span className="s">${s}</span></li>`)}</ul>
    </div>
    <figcaption>Real output for InsecureBankv2, an intentionally vulnerable test app.</figcaption>
  </figure>`;
}

const STEPS = [
  ["upload-simple", "Upload", "Drop an APK or AAB. It is validated, hashed with SHA-256 and unpacked in an isolated workspace."],
  ["magnifying-glass", "Analyse", "45 rules read the manifest, code, API use and libraries, then link related findings into attack chains."],
  ["wrench", "Fix", "Each finding shows its evidence, why it is exploitable and how to fix it. Download it all as a PDF."],
];
function How() {
  return html`<section id="how" className="section wrap how">
    <div className="how-intro"><h2>From APK to a ranked list of fixes</h2><p className="muted">Static analysis only. Nothing runs on a device and no API gets attacked.</p></div>
    <ol className="steps">${STEPS.map(([icon, t, d]) => html`<li key=${t}><${Icon} n=${icon} /><div><h3>${t}</h3><p className="muted">${d}</p></div></li>`)}</ol>
  </section>`;
}

const CATEGORIES = ["Hardcoded secrets", "Insecure data storage", "Insecure cryptography", "Exported components", "Insecure permissions",
  "Insecure WebView", "Cleartext traffic", "SSL/TLS validation", "Hardcoded API keys", "Hardcoded API secrets", "Insecure API endpoints",
  "HTTP endpoints", "Sensitive data in URLs", "Weak authentication", "TLS configuration", "Excessive permissions"];
const SHAP = [["log_call", 3.37], ["token: Log", 2.05], ["secret_word", 0.99]];  // real SHAP values for a logged password
function Checks() {
  return html`<section id="checks" className="section wrap">
    <h2 className="section-title">What every scan checks</h2>
    <div className="bento">
      <article className="cell cats"><h3>45 rules across 16 OWASP categories</h3><p>APK and API weaknesses, each mapped to OWASP MASVS and MASWE.</p>
        <ul className="pills">${CATEGORIES.map(c => html`<li key=${c}>${c}</li>`)}</ul></article>
      <article className="cell chain"><h3>Attack chains, not loose alerts</h3><p className="muted">Findings that combine are linked and ranked higher.</p>
        <div className="flow"><span className="step">Cleartext allowed</span><${Icon} n="plus" /><span className="step">http:// endpoint</span><${Icon} n="arrow-right" /><${Chip} v="HIGH" /></div></article>
      <article className="cell shap"><h3>ML risk that explains itself</h3><p className="muted">XGBoost trained on LVDAndro scores the evidence. SHAP shows why.</p>
        <div className="bars" role="img" aria-label="SHAP contributions: log_call 3.37, token Log 2.05, secret_word 0.99">
          ${SHAP.map(([n, v]) => html`<div className="bar" key=${n}><span className="mono">${n}</span><i style=${{width: `${(v / 3.37) * 100}%`}}></i><b>+${v}</b></div>`)}</div></article>
      <article className="cell libs"><${Icon} n="package" /><h3>Vulnerable libraries</h3><p className="muted">Bundled library versions are matched against OSV and GitHub advisories.</p></article>
      <article className="cell code"><h3>Evidence you can act on</h3>
        <pre><code>L27: SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");</code></pre><p>Fix: generate and keep keys in the Android Keystore.</p></article>
    </div>
  </section>`;
}

function Privacy() {
  return html`<section className="section privacy"><div className="wrap narrow"><${Icon} n="lock-key" />
    <h2>Your APK is deleted the moment its scan ends.</h2>
    <p className="muted">Decompiled code lives in a temporary workspace that is wiped after every scan. Only the findings and the file's SHA-256 are kept.</p>
  </div></section>`;
}

const WHY = [
  ["crosshair", "Fix what matters first", "Findings are ranked by how exploitable they are, not only by how severe they sound."],
  ["code", "Proof in every finding", "File, line and code for each issue, so a developer can confirm it in seconds."],
  ["chart-line-up", "Measured, not promised", "An F1 score of 0.97 on a benchmark of four intentionally vulnerable apps."],
  ["shield-check", "Safe to run", "Static analysis only. Nothing is installed, executed or attacked."],
  ["file-pdf", "Audit-ready reports", "Every finding maps to OWASP MASVS and MASWE and exports as a PDF."],
  ["gift", "Free to start", `${FREE} scans without an account, ${SIGNUP_LIMIT} with one.`],
];
function Why() {
  return html`<section id="why" className="section wrap why">
    <div className="why-intro"><h2>Why choose AndroGuard</h2>
      <p className="muted">Built to answer one question quickly: what should we fix first?</p>
      <p className="small muted">F1 measured on InsecureBankv2, AndroGoat, InsecureShop and OVAA, the same apps the rules were tuned on.</p></div>
    <ul className="why-grid">${WHY.map(([icon, t, d]) => html`<li key=${t}><${Icon} n=${icon} /><h3>${t}</h3><p className="muted">${d}</p></li>`)}</ul>
  </section>`;
}

const DEMO = [
  ["Drop your APK", `Drag it onto the page or pick it from your files. The first ${FREE} scans need no account.`],
  ["Watch the scan", "Validation, decompiling, 45 rules and scoring run on the server. Most scans finish in a few minutes."],
  ["Read the findings", "Highest risk first, each with its evidence, why it is exploitable and how to fix it."],
  ["Download the PDF", "One report for your team or auditor, mapped to OWASP MASVS."],
];
const SCREENS = [  // the real UI pieces with a real InsecureBankv2 scan
  () => html`<div className="mock">
    <div className="drop drag"><${Icon} n="upload-simple" /><div><strong>Drop your APK or AAB here</strong><span className="muted">${FREE} of ${FREE} free scans left</span></div></div>
    <div className="file-chip fly"><${Icon} n="android-logo" /><span className="mono">InsecureBankv2.apk</span><span className="muted">3.3 MB</span></div></div>`,
  () => html`<div className="mock"><strong>Scanning InsecureBankv2.apk</strong>
    <ol className="steps-progress">${STAGES.map(([label], i) => html`<li key=${label} className=${i < 2 ? "done" : i === 2 ? "now" : ""}>
      <${Icon} n=${i < 2 ? "check-circle" : i === 2 ? "circle-notch" : "circle"} />${label}</li>`)}</ol>
    <div className="meter"><i></i></div></div>`,
  () => html`<div className="mock"><div className="preview-risk"><${Chip} v="HIGH" />App risk 72/100</div>
    <ul className="rows">${SAMPLE_ROWS.slice(0, 3).map(([sev, t, c, s], i) => html`<li key=${t + c} className="reveal" style=${{"--d": `${i * 0.3}s`}}>
      <${Chip} v=${sev} /><span className="t">${t}<span className="c mono">${c}</span></span><span className="s">${s}</span></li>`)}</ul></div>`,
  () => html`<div className="mock">
    <div className="file-chip fly"><${Icon} n="file-pdf" /><span className="mono">InsecureBankv2-androguard.pdf</span><span className="muted">248 KB</span></div>
    <p className="muted">23 findings, highest risk first, mapped to OWASP MASVS and MASWE.</p>
    <span className="btn primary" style=${{justifySelf: "start"}}><${Icon} n="download-simple" />Download PDF</span></div>`,
];
function Demo() {  // auto-plays once on screen: the timer bar's animationend moves to the next step
  const [at, setAt] = useState(0), [playing, setPlaying] = useState(true), [seen, setSeen] = useState(false), box = useRef(null);
  useEffect(() => {
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setSeen(true); io.disconnect(); } }, {threshold: 0.4});
    io.observe(box.current);
    return () => io.disconnect();
  }, []);
  return html`<section id="demo" ref=${box} className="section wrap demo">
    <div>
      <h2>See a scan from start to finish</h2>
      <ol className="demo-steps">${DEMO.map(([t, d], i) => html`<li key=${t}>
        <button aria-current=${i === at ? "step" : undefined} onClick=${() => setAt(i)}>
          <span className="n">${i + 1}</span><span><strong>${t}</strong><span className="muted">${d}</span></span></button>
        ${i === at && html`<i className="timer" key=${at} style=${{animationPlayState: playing && seen ? "running" : "paused"}}
          onAnimationEnd=${() => setAt((at + 1) % DEMO.length)}></i>`}</li>`)}</ol>
      <button className="btn ghost sm demo-toggle" onClick=${() => setPlaying(!playing)}><${Icon} n=${playing ? "pause" : "play"} />${playing ? "Pause demo" : "Play demo"}</button>
    </div>
    <div className="play-card" aria-hidden="true">
      <div className="play-head"><span><${Icon} n="shield-check" />AndroGuard</span><span className="muted small">Step ${at + 1} of ${DEMO.length}</span></div>
      <div key=${`${at}-${seen}`}>${SCREENS[at]()}</div>
    </div>
  </section>`;
}

function FinalCta() {
  const {me} = useContext(Ctx);
  const user = me && me.user;
  const top = () => { window.scrollTo({top: 0, behavior: "smooth"}); document.getElementById("dropzone")?.focus({preventScroll: true}); };
  return html`<section className="section wrap final">
    <div><h2>Scan your first app</h2><p className="muted">${user ? `Your account includes up to ${SIGNUP_LIMIT} scans unless an admin sets another limit.` : `${FREE} scans are free. Create an account when you need more.`}</p></div>
    <button className="btn primary lg" onClick=${top}>${user ? "Start scan" : "Start free scan"}</button>
  </section>`;
}

const Footer = () => html`<footer className="footer wrap"><span>AndroGuard</span><span className="muted">Static security analysis for Android apps. Final year design project.</span></footer>`;

/* ---------------- accounts ---------------- */
function Auth({signup}) {
  const {refresh} = useContext(Ctx);
  const [form, setForm] = useState({name: "", email: "", password: ""}), [err, setErr] = useState(""), [busy, setBusy] = useState(false);
  const submit = async e => {
    e.preventDefault(); setBusy(true); setErr("");
    try {
      await api(`/api/auth/${signup ? "signup" : "login"}`, {method: "POST", json: signup ? form : {email: form.email, password: form.password}});
      await refresh(); go("/scans");
    } catch (x) { setErr(x.message); } finally { setBusy(false); }
  };
  const field = (key, label, type, auto, help) => html`<label className="field"><span>${label}</span>
    <input type=${type} name=${key} autoComplete=${auto} value=${form[key]} onChange=${e => setForm({...form, [key]: e.target.value})} />
    ${help && html`<small className="muted">${help}</small>`}</label>`;
  return html`<main className="auth wrap"><form className="auth-card" onSubmit=${submit} noValidate>
    <h1>${signup ? "Create your account" : "Sign in"}</h1>
    <p className="muted">${signup ? `Get ${SIGNUP_LIMIT} scans and a history of your reports. Your free scans come with you.` : "Welcome back. Your scans are where you left them."}</p>
    ${signup && field("name", "Name", "text", "name", "")}
    ${field("email", "Email", "email", "email", "")}
    ${field("password", "Password", "password", signup ? "new-password" : "current-password", signup ? "At least 8 characters" : "")}
    ${err && html`<p className="form-error" role="alert" style=${{margin: 0}}>${err}</p>`}
    <button className="btn primary block lg" disabled=${busy}>${busy ? "Please wait" : signup ? "Create account" : "Sign in"}</button>
    <p className="muted small">${signup ? html`Already have an account? <a href="#/signin">Sign in</a>` : html`New here? <a href="#/signup">Create account</a>`}</p>
  </form></main>`;
}

/* ---------------- scans ---------------- */
function ScanTable({scans, admin, onDelete}) {
  return html`<div className="scroll-x"><table className="table">
    <thead><tr><th>File</th>${admin && html`<th>Owner</th>`}<th>Status</th><th>App risk</th><th>Findings</th><th>Started</th>${onDelete && html`<th><span className="sr-only">Actions</span></th>`}</tr></thead>
    <tbody>${scans.map(s => html`<tr key=${s.id} className="click" tabIndex="0" onClick=${() => go(`/scans/${s.id}`)}
        onKeyDown=${e => e.key === "Enter" && go(`/scans/${s.id}`)}>
      <td><strong style=${{fontWeight: 500}}>${s.filename}</strong>${s.status === "failed" && html`<span className="small muted" style=${{display: "block"}}>${(s.error || "").slice(-90)}</span>`}</td>
      ${admin && html`<td className="muted">${s.owner || "Free trial"}</td>`}
      <td><${Chip} v=${s.status} /></td>
      <td>${s.risk ? html`<span style=${{display: "inline-flex", gap: "8px", alignItems: "center"}}><${Chip} v=${s.risk.level} />${s.risk.score}</span>` : html`<span className="muted">n/a</span>`}</td>
      <td>${s.status === "done" ? s.findings : html`<span className="muted">n/a</span>`}</td>
      <td className="muted">${date(s.created_at)}</td>
      ${onDelete && html`<td><button className="btn ghost sm danger" onClick=${e => { e.stopPropagation(); onDelete(s); }}>Delete</button></td>`}
    </tr>`)}</tbody></table></div>`;
}

function MyScans() {
  const {me} = useContext(Ctx);
  const [scans, err] = useLoad("/api/scans", list => list.some(active));
  const q = me && me.quota, user = me && me.user;
  return html`<main className="page wrap">
    <div className="page-head"><div><h1>My scans</h1>${q && html`<p className="muted">${q.limit == null ? "Unlimited scans" : `${q.used} of ${q.limit} ${user ? "" : "free "}scans used`}</p>`}</div>
      ${user && html`<a className="btn primary" href="#/">Start scan</a>`}</div>
    ${err ? html`<p className="form-error">${err}</p>` : !scans ? html`<${Skeleton} />` : scans.length === 0
      ? html`<div className="empty"><${Icon} n="file-magnifying-glass" /><h2>No scans yet</h2><p className="muted">Upload an APK or AAB and its report shows up here.</p><a className="btn primary" href="#/">Scan an app</a></div>`
      : html`<${ScanTable} scans=${scans} />`}
  </main>`;
}

const STAGES = [["Validating the package", "valid"], ["Decompiling with apktool and jadx", "Decompiling"], ["Running 45 rules and the dependency check", "Running"], ["Scoring exploitability and ML risk", "Correlating"]];

// Phone mockup beside a running scan: one looping illustration per pipeline stage (not live data).
const CODE = [
  "public class LoginActivity extends Activity {",
  "  static final String KEY = \"4f9c2e1a7b\";",
  "  protected void onCreate(Bundle state) {",
  "    super.onCreate(state);",
  "    prefs = getSharedPreferences(\"auth\", 0);",
  "    prefs.edit().putString(\"pwd\", pwd).apply();",
  "    Log.d(\"login\", \"token=\" + token);",
  "    web.getSettings().setJavaScriptEnabled(true);",
  "    api = new URL(\"http://api.example.com\");",
  "  }",
  "}",
];
const HITS = {1: "high", 5: "med", 6: "med", 8: "med"};  // lines the rule scan lights up
const PHONE = [
  () => html`<div className="pm-center"><div className="pm-icon"><${Icon} n="android-logo" /></div>
    <ul className="pm-checks">${["ZIP structure", "AndroidManifest.xml", "SHA-256 fingerprint"].map((t, i) =>
      html`<li key=${t} className="reveal" style=${{"--d": `${0.3 + i * 0.6}s`}}><${Icon} n="check-circle" />${t}</li>`)}</ul></div>`,
  () => html`<div className="pm-dex mono"><span>classes.dex</span><b>64 65 78 0A 30 33 35 00</b></div>
    <div className="pm-arrow"><${Icon} n="arrow-down" />jadx turns the bytecode back into Java</div>
    <div className="pm-code mono"><div className="stream">${[...CODE, ...CODE].map((l, i) => html`<div key=${i}>${l}</div>`)}</div></div>`,
  () => html`<div className="pm-code mono scan">${CODE.map((l, i) => html`<div key=${i} className=${HITS[i] ? `hit ${HITS[i]}` : ""}
      style=${{"--t": `${((10 + (i + 0.5) * 19) / 290) * 3}s`}}>${l}</div>`)}<i className="beam"></i></div>
    <div className="pm-tags"><span className="chip high">Hardcoded key</span><span className="chip medium">Secret in logs</span><span className="chip medium">Cleartext HTTP</span></div>
    <p className="muted">Checking 16 OWASP categories</p>`,
  () => html`<div className="pm-bars">${[["Exploitability", 0.8], ["Attack chains", 0.55], ["ML risk", 0.4]].map(([t, w]) =>
      html`<div key=${t}><span>${t}</span><i style=${{width: `${w * 100}%`}}></i></div>`)}</div>
    <p className="muted">Ranking every finding by severity, exploitability and confidence.</p>`,
];
const Phone = ({at, file}) => html`<div className="phone" aria-hidden="true"><div className="phone-screen">
  <div className="pm-head"><${Icon} n="android-logo" /><div><b>${file}</b><span><i className="live"></i>Working: ${["validating", "decompiling", "running rules", "scoring"][at]}</span></div></div>
  <div className="pm-body" key=${at}>${PHONE[at]()}</div>
</div></div>`;
function ScanPage({id}) {
  const [scan, err, load] = useLoad(`/api/scans/${id}`, active);
  const cancel = () => api(`/api/scans/${id}/cancel`, {method: "POST"}).catch(() => {}).then(load);
  if (err) return html`<main className="page wrap"><div className="empty"><${Icon} n="warning-circle" /><h2>${err}</h2><a className="btn" href="#/scans">Back to my scans</a></div></main>`;
  if (!scan) return html`<main className="page wrap"><${Skeleton} rows=${4} /></main>`;
  if (active(scan)) {
    const at = Math.max(0, STAGES.findIndex(([, key]) => (scan.progress || "").includes(key)));
    return html`<main className="page wrap scan-live"><div className="panel" aria-live="polite">
      <h1 style=${{fontSize: "24px"}}>Scanning ${scan.filename}</h1><p className="muted" style=${{marginTop: "6px"}}>This usually takes one to four minutes. You can leave this page open.</p>
      <ol className="steps-progress">${STAGES.map(([label], i) => html`<li key=${label} className=${i < at ? "done" : i === at ? "now" : ""}>
        <${Icon} n=${i < at ? "check-circle" : i === at ? "circle-notch" : "circle"} />${label}</li>`)}</ol>
      <button className="btn ghost sm" style=${{marginTop: "20px"}} onClick=${cancel}>Cancel scan</button></div>
      <${Phone} at=${at} file=${scan.filename} /></main>`;
  }
  if (scan.status === "cancelled") return html`<main className="page wrap"><div className="empty"><${Icon} n="x-circle" />
    <h2>This scan was cancelled</h2><p className="muted">Cancelled and failed scans do not use up your scans.</p><a className="btn primary" href="#/">Scan an app</a></div></main>`;
  if (scan.status === "failed") return html`<main className="page wrap"><div className="empty"><${Icon} n="warning-circle" />
    <h2>This scan could not finish</h2><p className="muted">${(scan.error || "").slice(-240)}</p><a className="btn primary" href="#/">Try another file</a></div></main>`;
  return html`<${Report} scan=${scan} />`;
}

function Report({scan}) {
  const [sev, setSev] = useState("ALL");
  const r = scan.report, risk = r.risk, findings = r.findings;
  const counts = findings.reduce((c, f) => ({...c, [f.severity]: (c[f.severity] || 0) + 1}), {});
  const shown = sev === "ALL" ? findings : findings.filter(f => f.severity === sev);
  return html`<main className="page wrap">
    <div className="page-head"><div><a className="link small" href="#/scans">My scans</a><h1 style=${{marginTop: "6px"}}>${r.file}</h1>
      <p className="mono small muted" style=${{wordBreak: "break-all"}}>SHA-256 ${r.sha256}</p></div>
      <div style=${{display: "flex", gap: "8px"}}><a className="btn" href=${`/api/scans/${scan.id}/report.html`} target="_blank" rel="noopener">HTML report</a>
        <a className="btn primary" href=${`/api/scans/${scan.id}/report.pdf`}><${Icon} n="download-simple" />Download PDF</a></div></div>
    <dl className="summary">
      <div><dt>App risk</dt><dd><${Chip} v=${risk.level} />${risk.score}<small>/100</small></dd></div>
      <div><dt>Findings</dt><dd>${findings.length}</dd></div>
      <div><dt>Highly exploitable</dt><dd>${risk.exploitability.HIGH}</dd></div>
      <div><dt>In attack chains</dt><dd>${risk.in_attack_chains.length}</dd></div>
    </dl>
    <div className="panel">
      <h2>Findings, highest risk first</h2>
      <div className="filters" role="group" aria-label="Filter by severity">${["ALL", "HIGH", "MEDIUM", "LOW"].map(v => html`<button key=${v} aria-pressed=${sev === v} onClick=${() => setSev(v)}>
        ${v === "ALL" ? `All ${findings.length}` : `${title(v)} ${counts[v] || 0}`}</button>`)}</div>
      ${shown.length ? shown.map(f => html`<${Finding} key=${f.id} f=${f} />`) : html`<p className="muted">Nothing at this severity.</p>`}
    </div>
    ${r.data_flow_status && html`<div className="panel">
      <h2>Data flows (FlowDroid)</h2><p className="muted">${r.data_flow_status}</p>
      ${(r.data_flows || []).length > 0 && html`<ul className="flows mono">${r.data_flows.slice(0, 30).map((f, i) => html`<li key=${i}>
        <span>${f.source} <span className="muted">line ${f.source_line}</span></span><${Icon} n="arrow-right" />
        <span>${f.sink} <span className="muted">line ${f.sink_line}</span></span><span className="muted">in ${f.method}</span></li>`)}</ul>`}
    </div>`}
  </main>`;
}

function Finding({f}) {
  const [open, setOpen] = useState(false);
  return html`<div className="finding">
    <button aria-expanded=${open} onClick=${() => setOpen(!open)}>
      <span className="score">${Number(f.risk_score).toFixed(1)}</span><span className="sev"><${Chip} v=${f.severity} /></span>
      <span style=${{minWidth: 0}}><span className="ttl">${f.title}</span><span className="sub mono">${f.affected_component}</span></span>
      <span className="ex small muted">${title(f.exploitability)} exploitability</span><${Icon} n=${open ? "caret-up" : "caret-down"} />
    </button>
    ${open && html`<div className="body">
      <p>${f.description}</p>
      ${f.evidence && f.evidence.length > 0 && html`<div><h4>Evidence</h4><div className="evidence mono">${f.evidence.join("\n")}</div></div>`}
      <div><h4>Why this exploitability</h4><ul>${(f.exploit_factors || []).map((x, i) => html`<li key=${i}>${x}</li>`)}</ul></div>
      ${f.related && f.related.length > 0 && html`<div><h4>Linked findings</h4><p className="mono small">${f.related.join(", ")}</p></div>`}
      <div><h4>OWASP</h4><p>${[...(f.masvs || []), ...(f.maswe || [])].join(", ")}</p></div>
      ${f.confidence != null && html`<div><h4>Detection confidence</h4><p>${Math.round(f.confidence * 100)}%</p></div>`}
      ${(f.codebert_tokens || []).length > 0 && html`<div><h4>CodeBERT attention</h4>
        <p>${Math.round(f.codebert_score * 100)}% likely vulnerable. Tokens the model attended to most:</p>
        <p className="tokens">${f.codebert_tokens.map(t => html`<code key=${t}>${t}</code>`)}</p></div>`}
      <div><h4>How to fix</h4><p>${f.remediation}</p></div>
    </div>`}
  </div>`;
}

/* ---------------- CRM ---------------- */
function Admin({tab}) {
  const {me} = useContext(Ctx);
  if (!me) return html`<main className="page wrap"><${Skeleton} /></main>`;
  if (!me.user) return html`<main className="page wrap"><div className="empty"><${Icon} n="lock-key" /><h2>Sign in to open the admin area</h2><a className="btn primary" href="#/signin">Sign in</a></div></main>`;
  if (!isAdmin(me.user)) return html`<main className="page wrap"><div className="empty"><${Icon} n="lock-key" /><h2>This area is for admins</h2><a className="btn" href="#/scans">Go to my scans</a></div></main>`;
  const tabs = [["overview", "Overview", "chart-bar"], ["users", "Users", "users"], ["scans", "Scans", "files"]];
  return html`<main className="admin wrap">
    <nav className="tabs" aria-label="Admin">${tabs.map(([k, label, icon]) => html`<a key=${k} href=${`#/admin/${k}`} aria-current=${tab === k ? "page" : undefined}><${Icon} n=${icon} />${label}</a>`)}</nav>
    <section>${tab === "users" ? html`<${Users} me=${me.user} />` : tab === "scans" ? html`<${AllScans} />` : html`<${Overview} />`}</section>
  </main>`;
}

function Overview() {
  const [s, err] = useLoad("/api/admin/stats");
  if (err) return html`<p className="form-error">${err}</p>`;
  if (!s) return html`<${Skeleton} rows=${4} />`;
  const conversion = s.trial_devices ? Math.round((100 * s.converted_devices) / s.trial_devices) : 0;
  const peak = Math.max(1, ...s.per_day.map(d => d.scans));
  return html`<div>
    <h1>Overview</h1>
    <dl className="summary">
      <div><dt>Users</dt><dd>${s.users}</dd><small className="muted">${s.new_users_7d} new this week</small></div>
      <div><dt>Scans</dt><dd>${s.scans}</dd><small className="muted">${s.scans_7d} this week</small></div>
      <div><dt>High-risk results</dt><dd>${s.high_risk}</dd><small className="muted">${s.failed} failed scan${s.failed === 1 ? "" : "s"}</small></div>
      <div><dt>Trial to account</dt><dd>${conversion}%</dd><small className="muted">${s.converted_devices} of ${s.trial_devices} trial browser${s.trial_devices === 1 ? "" : "s"}</small></div>
    </dl>
    <div className="panel"><h2>Scans in the last 14 days</h2>
      <div className="chart" role="img" aria-label=${s.per_day.map(d => `${d.date}: ${d.scans}`).join(", ")}>
        ${s.per_day.map(d => html`<div className="col" key=${d.date} title=${`${d.date}: ${d.scans} scans`}>
          <div style=${{height: `${(d.scans / peak) * 100}%`}}><span className=${d.scans === peak && d.scans > 0 ? "peak" : ""}>${d.scans}</span></div>
          <small>${new Date(d.date + "T00:00").getDate()}</small></div>`)}</div></div>
    <div className="panel"><h2>Recent scans</h2>${s.recent.length ? html`<${ScanTable} scans=${s.recent} admin />` : html`<p className="muted">No scans yet.</p>`}</div>
  </div>`;
}

function Users({me}) {
  const [q, setQ] = useState(""), [rows, setRows] = useState(null), [err, setErr] = useState(""), [open, setOpen] = useState(null);
  useEffect(() => {
    const t = setTimeout(() => api(`/api/admin/users?q=${encodeURIComponent(q)}`).then(setRows).catch(e => setErr(e.message)), 250);
    return () => clearTimeout(t);
  }, [q]);
  const superadmin = me.role === "superadmin";
  const editable = u => u.role !== "superadmin" && (superadmin || u.role === "user");
  const patch = async (u, body) => {
    try { const next = await api(`/api/admin/users/${u.id}`, {method: "PATCH", json: body}); setRows(rs => rs.map(r => (r.id === next.id ? next : r))); setErr(""); }
    catch (e) { setErr(e.message); }
  };
  const remove = async u => {
    if (!confirm(`Delete ${u.email} and all of their scans? This cannot be undone.`)) return;
    try { await api(`/api/admin/users/${u.id}`, {method: "DELETE"}); setRows(rs => rs.filter(r => r.id !== u.id)); } catch (e) { setErr(e.message); }
  };
  return html`<div>
    <h1>Users</h1>
    <div className="toolbar"><input className="input" type="search" placeholder="Search by name or email" aria-label="Search users" value=${q} onChange=${e => setQ(e.target.value)} /></div>
    ${err && html`<p className="form-error" role="alert">${err}</p>`}
    ${!rows ? html`<${Skeleton} />` : rows.length === 0 ? html`<div className="empty"><${Icon} n="users" /><h2>No users match</h2><p className="muted">Try another search.</p></div>`
    : html`<div className="scroll-x"><table className="table">
      <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Scans used</th><th>Limit</th><th>Last sign-in</th><th><span className="sr-only">Actions</span></th></tr></thead>
      <tbody>${rows.map(u => html`<${React.Fragment} key=${u.id}>
        <tr>
          <td><strong style=${{fontWeight: 500}}>${u.name || u.email.split("@")[0]}</strong><span className="small muted" style=${{display: "block"}}>${u.email}</span></td>
          <td>${superadmin && u.role !== "superadmin"
            ? html`<select className="input" style=${{height: "34px"}} aria-label=${`Role of ${u.email}`} value=${u.role} onChange=${e => patch(u, {role: e.target.value})}><option value="user">User</option><option value="admin">Admin</option></select>`
            : title(u.role)}</td>
          <td><${Chip} v=${u.status} /></td>
          <td>${u.scans_used}</td>
          <td>${editable(u) ? html`<input className="input limit" type="number" min="0" aria-label=${`Scan limit of ${u.email}`} placeholder="None"
              defaultValue=${u.scan_limit == null ? "" : u.scan_limit} onBlur=${e => { const v = e.target.value.trim(); const next = v === "" ? null : Number(v);
                if (next !== u.scan_limit) patch(u, {scan_limit: next}); }} />` : html`<span className="muted">${u.scan_limit == null ? "None" : u.scan_limit}</span>`}</td>
          <td className="muted">${date(u.last_login_at) || "Never"}</td>
          <td style=${{whiteSpace: "nowrap"}}>
            <button className="btn ghost sm" onClick=${() => setOpen(open === u.id ? null : u.id)} aria-expanded=${open === u.id}>Notes</button>
            ${editable(u) && html` <button className="btn ghost sm" onClick=${() => patch(u, {status: u.status === "active" ? "blocked" : "active"})}>${u.status === "active" ? "Block" : "Unblock"}</button>`}
            ${superadmin && u.role !== "superadmin" && html` <button className="btn ghost sm danger" onClick=${() => remove(u)}>Delete</button>`}</td>
        </tr>
        ${open === u.id && html`<tr><td colSpan="7" className="notes"><${Notes} user=${u} onSave=${notes => patch(u, {notes})} /></td></tr>`}
      </${React.Fragment}>`)}</tbody></table></div>`}
  </div>`;
}

function Notes({user, onSave}) {
  const [text, setText] = useState(user.notes || "");
  return html`<label className="field"><span>Notes about ${user.email}</span>
    <textarea value=${text} maxLength="2000" onChange=${e => setText(e.target.value)} placeholder="Where they came from, what they need, follow-ups"></textarea>
    <span><button className="btn sm" onClick=${() => onSave(text)} disabled=${text === (user.notes || "")}>Save notes</button></span></label>`;
}

function AllScans() {
  const [q, setQ] = useState(""), [status, setStatus] = useState(""), [rows, setRows] = useState(null), [err, setErr] = useState("");
  useEffect(() => {
    const t = setTimeout(() => api(`/api/admin/scans?q=${encodeURIComponent(q)}&status=${status}`).then(setRows).catch(e => setErr(e.message)), 250);
    return () => clearTimeout(t);
  }, [q, status]);
  const remove = async s => {
    if (!confirm(`Delete the scan of ${s.filename}? Its report is removed for everyone.`)) return;
    try { await api(`/api/admin/scans/${s.id}`, {method: "DELETE"}); setRows(rs => rs.filter(r => r.id !== s.id)); } catch (e) { setErr(e.message); }
  };
  return html`<div>
    <h1>Scans</h1>
    <div className="toolbar">
      <input className="input" type="search" placeholder="Search by file or email" aria-label="Search scans" value=${q} onChange=${e => setQ(e.target.value)} />
      <select className="input" aria-label="Filter by status" value=${status} onChange=${e => setStatus(e.target.value)}>
        <option value="">All statuses</option><option value="done">Done</option><option value="running">Running</option><option value="queued">Queued</option><option value="failed">Failed</option><option value="cancelled">Cancelled</option></select>
    </div>
    ${err && html`<p className="form-error" role="alert">${err}</p>`}
    ${!rows ? html`<${Skeleton} />` : rows.length === 0 ? html`<div className="empty"><${Icon} n="files" /><h2>No scans match</h2><p className="muted">Try another search or status.</p></div>`
      : html`<${ScanTable} scans=${rows} admin onDelete=${remove} />`}
  </div>`;
}

ReactDOM.createRoot(document.getElementById("root")).render(html`<${App} />`);
