// Minimal backend for the UPI gateway test. Keys stay HERE (env vars), never in the browser.
// Run:  npm i express  &&  cp .env.example .env  &&  node --env-file=.env server.js   (Node 20+)
import express from "express";
import { createHmac, timingSafeEqual } from "node:crypto";

const { UPI_GATEWAY_URL, UPI_GATEWAY_API_KEY, UPI_WEBHOOK_SECRET,
        CALLBACK_URL, WEBHOOK_URL, ALLOWED_ORIGIN = "*", PORT = 3000 } = process.env;

const app = express();
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); } }));

app.use((req, res, next) => {
  res.set({
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  });
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const gw = (path, opts = {}) => fetch(`${UPI_GATEWAY_URL}${path}`, {
  ...opts,
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${UPI_GATEWAY_API_KEY}` },
});

const paid = new Map(); // orderId -> {utr, amountInr, at}  (test only; use a DB in production)

// 1. Create checkout session -> frontend redirects to checkoutUrl
app.post("/api/create-payment", async (req, res) => {
  try {
    const { orderId, amountInr, description, callbackUrl } = req.body || {};
    if (!orderId || !(Number(amountInr) > 0)) return res.status(400).json({ error: "orderId and amountInr required" });
    const r = await gw("/api/v1/checkout/sessions", {
      method: "POST",
      body: JSON.stringify({
        orderId, amountInr: Number(amountInr),
        description: description || `Order ${orderId}`,
        callbackUrl: callbackUrl || CALLBACK_URL,
        webhookUrl: WEBHOOK_URL,
      }),
    });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json({ checkoutUrl: data.checkoutUrl, sessionId: data.session.id });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// 2. Verify session status (used by the confirmation view)
app.get("/api/session/:id", async (req, res) => {
  try {
    const r = await gw(`/api/v1/checkout/sessions/${encodeURIComponent(req.params.id)}`);
    res.status(r.status).json(await r.json());
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// 3. Signed webhook (set WEBHOOK_URL to this endpoint's public https URL)
app.post("/api/upi-webhook", (req, res) => {
  const parts = Object.fromEntries(String(req.get("x-upi-signature") || "").split(",").map(s => s.trim().split("=")));
  const ts = Number(parts.t);
  if (!Number.isFinite(ts) || !parts.v1 || Math.abs(Date.now() / 1000 - ts) > 300)
    return res.status(401).json({ error: "Expired or malformed signature" });

  const sign = body => createHmac("sha256", UPI_WEBHOOK_SECRET).update(`${ts}.${body}`, "utf8").digest("hex");
  const ok = body => { const e = sign(body); return parts.v1.length === e.length &&
    timingSafeEqual(Buffer.from(e, "hex"), Buffer.from(parts.v1, "hex")); };
  if (!(ok(req.rawBody) || ok(JSON.stringify(req.body)))) return res.status(401).json({ error: "Invalid signature" });

  const { event, data } = req.body;
  if (event === "payment.captured" && !paid.has(data.orderId)) // idempotent
    paid.set(data.orderId, { utr: data.utr, amountInr: data.amountInr, at: Date.now() });
  res.json({ received: true });
});

app.get("/api/order/:orderId", (req, res) => res.json(paid.get(req.params.orderId) || { status: "NOT_PAID" }));

app.listen(PORT, () => console.log(`UPI test backend on :${PORT}`));
