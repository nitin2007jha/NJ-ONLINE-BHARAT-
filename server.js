// NJ ONLINE BHARAT – UPI gateway test (zero dependencies, Node 20+)
// Ek hi server: page (/) + payment API + webhook. Bas deploy karo, koi URL config nahi.
//
// Cloud Run :  gcloud run deploy upi-test --source . --region us-west1 --allow-unauthenticated --max-instances 1
// Render/Railway/VPS :  npm start   (PORT env automatic)
import http from "node:http";
import { readFile } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// ---- Config (env vars ko priority; na ho to neeche ke defaults) ----------------
// ⚠️ Is file ko public GitHub repo me push mat karna. Better: deploy par env vars set karo.
const GATEWAY_URL    = process.env.UPI_GATEWAY_URL    || "https://upi-gateway-306595059779.us-west1.run.app";
const API_KEY        = process.env.UPI_GATEWAY_API_KEY || "upi_live_deee4cc86281801d6b59ae58";
const WEBHOOK_SECRET = process.env.UPI_WEBHOOK_SECRET  || "whsec_live_f43ca8296cb5f7e93430d27ce1322cbac830de0a";
const AMOUNT_INR     = Number(process.env.PLAN_AMOUNT_INR || 1);   // ₹1 fixed, server decide karta hai
const PORT           = Number(process.env.PORT || 3000);
// ---------------------------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));
const paid = new Map();     // orderId -> { utr, amountInr, sessionId, at }
const hooks = [];           // last webhook deliveries (valid + invalid) for debugging

const origin = req => {
  const proto = (req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
  const host  = (req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  return `${proto}://${host}`;
};
const send = (res, code, body, type = "application/json") => {
  res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store" });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
};
const readBody = req => new Promise((ok, no) => {
  let b = ""; req.on("data", c => { b += c; if (b.length > 1e6) req.destroy(); });
  req.on("end", () => ok(b)); req.on("error", no);
});
const gw = (path, opts = {}) => fetch(GATEWAY_URL + path, {
  ...opts, headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
});

function verifySignature(header, raw) {
  const parts = Object.fromEntries(String(header || "").split(",").map(s => s.trim().split("=")));
  const ts = Number(parts.t);
  if (!Number.isFinite(ts) || !parts.v1) return "malformed signature";
  if (Math.abs(Date.now() / 1000 - ts) > 300) return "expired (>300s)";
  const check = body => {
    const exp = createHmac("sha256", WEBHOOK_SECRET).update(`${ts}.${body}`, "utf8").digest("hex");
    return exp.length === parts.v1.length && timingSafeEqual(Buffer.from(exp, "hex"), Buffer.from(parts.v1, "hex"));
  };
  let canon = raw; try { canon = JSON.stringify(JSON.parse(raw)); } catch {}
  return check(raw) || check(canon) ? null : "signature mismatch";
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const path = url.pathname;
  try {
    if (req.method === "GET" && (path === "/" || path === "/index.html"))
      return send(res, 200, await readFile(join(here, "index.html"), "utf8"), "text/html; charset=utf-8");

    if (req.method === "GET" && path === "/health") return send(res, 200, { ok: true });

    // 1. Checkout session banao
    if (req.method === "POST" && path === "/api/create-payment") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const orderId = String(body.orderId || "ORD-" + Date.now()).slice(0, 60);
      const o = origin(req);
      const r = await gw("/api/v1/checkout/sessions", {
        method: "POST",
        body: JSON.stringify({
          orderId, amountInr: AMOUNT_INR, description: "Pro Plan Upgrade",
          callbackUrl: o + "/", webhookUrl: o + "/api/upi-webhook",
        }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok || !data.checkoutUrl) return send(res, r.status || 502, { error: "gateway error", details: data });
      return send(res, 200, { checkoutUrl: data.checkoutUrl, sessionId: data.session?.id, orderId });
    }

    // 2. Session status verify
    if (req.method === "GET" && path.startsWith("/api/session/")) {
      const id = decodeURIComponent(path.split("/").pop());
      const r = await gw(`/api/v1/checkout/sessions/${encodeURIComponent(id)}`);
      const data = await r.json().catch(() => ({}));
      return send(res, r.status, { ...data, webhook: paid.get(data.session?.orderId) || null });
    }

    // 3. Signed webhook
    if (req.method === "POST" && path === "/api/upi-webhook") {
      const raw = await readBody(req);
      const bad = verifySignature(req.headers["x-upi-signature"], raw);
      let payload = {}; try { payload = JSON.parse(raw); } catch {}
      hooks.unshift({ at: new Date().toISOString(), event: payload.event, orderId: payload.data?.orderId,
                      utr: payload.data?.utr, valid: !bad, reason: bad || undefined });
      hooks.length = Math.min(hooks.length, 20);
      if (bad) return send(res, 401, { error: bad });
      const d = payload.data || {};
      if (payload.event === "payment.captured" && d.orderId && !paid.has(d.orderId))   // idempotent
        paid.set(d.orderId, { utr: d.utr, amountInr: d.amountInr, sessionId: d.sessionId, at: Date.now() });
      return send(res, 200, { received: true });
    }

    if (req.method === "GET" && path === "/api/webhook-log") return send(res, 200, { hooks });

    send(res, 404, { error: "not found" });
  } catch (e) {
    send(res, 500, { error: String(e.message || e) });
  }
});

server.listen(PORT, () => console.log(`UPI test running on :${PORT}`));
