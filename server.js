import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import cors from 'cors';
import cron from 'node-cron';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(join(__dirname, 'public')));

// ── Database ────────────────────────────────────────────────────
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function db(sql, params = []) {
  const client = await pool.connect();
  try { return await client.query(sql, params); }
  finally { client.release(); }
}

async function initDB() {
  await db(`
    CREATE TABLE IF NOT EXISTS kv_store (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS graph_tokens (
      id INT PRIMARY KEY DEFAULT 1,
      access_token TEXT,
      refresh_token TEXT,
      expires_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS processed_emails (
      message_id TEXT PRIMARY KEY,
      processed_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // Seed default password
  const existing = await db(`SELECT value FROM kv_store WHERE key = 'auth_password'`);
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash(process.env.DASHBOARD_PASSWORD || 'wholesale2026', 10);
    await db(`INSERT INTO kv_store (key, value) VALUES ('auth_password', $1)`, [JSON.stringify(hash)]);
    console.log('Default password seeded — change via settings');
  }
  console.log('✅ Database ready');
}

// ── Auth middleware ─────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'ws-secret-change-me');
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── Auth routes ─────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { password } = req.body;
    const result = await db(`SELECT value FROM kv_store WHERE key = 'auth_password'`);
    if (result.rows.length === 0) return res.status(401).json({ error: 'No password set' });
    // value may be stored as a JSON string or raw string — handle both
    let hash = result.rows[0].value;
    if (typeof hash === 'object') hash = JSON.stringify(hash);
    hash = hash.replace(/^"|"$/g, ''); // strip surrounding quotes if double-encoded
    const valid = await bcrypt.compare(password, hash);
    if (!valid) return res.status(401).json({ error: 'Incorrect password' });
    const token = jwt.sign({ role: 'staff' }, process.env.JWT_SECRET || 'ws-secret-change-me', { expiresIn: '30d' });
    res.json({ token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password too short (min 6)' });
    const hash = await bcrypt.hash(password, 10);
    await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ('auth_password', $1, NOW())
              ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`, [JSON.stringify(hash)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── KV Store (replaces window.storage) ─────────────────────────
app.get('/api/store/:key', auth, async (req, res) => {
  try {
    const result = await db(`SELECT value FROM kv_store WHERE key = $1`, [req.params.key]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ key: req.params.key, value: result.rows[0].value });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/store/:key', auth, async (req, res) => {
  try {
    await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ($1, $2, NOW())
              ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=NOW()`,
              [req.params.key, JSON.stringify(req.body.value)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/store/:key', auth, async (req, res) => {
  try {
    await db(`DELETE FROM kv_store WHERE key = $1`, [req.params.key]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Microsoft Graph OAuth ───────────────────────────────────────
const GRAPH_SCOPES = 'offline_access Mail.Read Mail.ReadWrite';
const authBase = () => `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0`;

app.get('/api/graph/connect', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.AZURE_CLIENT_ID,
    response_type: 'code',
    redirect_uri: process.env.GRAPH_REDIRECT_URI,
    scope: GRAPH_SCOPES,
    response_mode: 'query'
  });
  res.redirect(`${authBase()}/authorize?${params}`);
});

app.get('/api/graph/callback', async (req, res) => {
  try {
    const resp = await fetch(`${authBase()}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.AZURE_CLIENT_ID,
        client_secret: process.env.AZURE_CLIENT_SECRET,
        code: req.query.code,
        redirect_uri: process.env.GRAPH_REDIRECT_URI,
        grant_type: 'authorization_code',
        scope: GRAPH_SCOPES
      })
    });
    const tokens = await resp.json();
    if (tokens.error) throw new Error(tokens.error_description);
    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000);
    await db(`INSERT INTO graph_tokens (id, access_token, refresh_token, expires_at, updated_at)
              VALUES (1, $1, $2, $3, NOW())
              ON CONFLICT (id) DO UPDATE SET access_token=$1, refresh_token=$2, expires_at=$3, updated_at=NOW()`,
              [tokens.access_token, tokens.refresh_token, expiresAt]);
    console.log('✅ Microsoft Graph connected');
    res.redirect('/?connected=true');
  } catch (e) {
    console.error('Graph OAuth error:', e.message);
    res.redirect('/?error=graph_auth_failed');
  }
});

app.get('/api/graph/status', auth, async (req, res) => {
  try {
    const result = await db(`SELECT expires_at, updated_at FROM graph_tokens WHERE id = 1`);
    if (result.rows.length === 0) return res.json({ connected: false });
    res.json({ connected: true, expiresAt: result.rows[0].expires_at, connectedAt: result.rows[0].updated_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/graph/disconnect', auth, async (req, res) => {
  try {
    await db(`DELETE FROM graph_tokens WHERE id = 1`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Token refresh helper ────────────────────────────────────────
async function getAccessToken() {
  const result = await db(`SELECT * FROM graph_tokens WHERE id = 1`);
  if (result.rows.length === 0) throw new Error('Graph not connected');
  const token = result.rows[0];
  if (new Date(token.expires_at) < new Date(Date.now() + 5 * 60 * 1000)) {
    const resp = await fetch(`${authBase()}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.AZURE_CLIENT_ID,
        client_secret: process.env.AZURE_CLIENT_SECRET,
        refresh_token: token.refresh_token,
        grant_type: 'refresh_token',
        scope: GRAPH_SCOPES
      })
    });
    const tokens = await resp.json();
    if (tokens.error) throw new Error('Token refresh failed');
    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000);
    await db(`UPDATE graph_tokens SET access_token=$1, expires_at=$2, updated_at=NOW() WHERE id=1`,
              [tokens.access_token, expiresAt]);
    return tokens.access_token;
  }
  return token.access_token;
}

// ── Ordermentum email parser ────────────────────────────────────
function parseOrdermentumEmail(subject, bodyText) {
  // Ordermentum sends: subject = "Invoice - Wholesale State Cold Pressed Juices #OMI17839"
  // Body contains order number as #OMO17839

  const omoMatch = (bodyText + ' ' + subject).match(/OMO\d+/);
  if (!omoMatch) return null;
  const orderNumber = omoMatch[0];

  // Clean body
  const clean = bodyText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

  // Customer name — "To Black Sheep 59 Hanson Street..."
  let customer = 'Unknown';
  const toMatch = clean.match(/(?:^|\s)To\s+([A-Z][A-Za-z0-9 &'\-\.]+?)\s+\d{1,4}\s+[A-Z]/);
  if (toMatch) customer = toMatch[1].trim();

  // Delivery date — "Delivery Date 12 Mar 2026"
  let dueDate = '';
  const delivMatch = clean.match(/Delivery\s+Date[:\s]+(\d{1,2}\s+\w+\s+\d{4})/i);
  if (delivMatch) {
    const d = new Date(delivMatch[1]);
    if (!isNaN(d)) {
      dueDate = String(d.getDate()).padStart(2,'0') + '/' + String(d.getMonth()+1).padStart(2,'0') + '/' + d.getFullYear();
    } else {
      dueDate = delivMatch[1].trim();
    }
  }

  // Suburb and state from address
  let suburb = '', state = '';
  const addrMatch = clean.match(/\bVIC\b|\bNSW\b|\bQLD\b|\bSA\b|\bWA\b|\bTAS\b|\bACT\b|\bNT\b/);
  if (addrMatch) state = addrMatch[0];
  const suburbMatch = clean.match(/([A-Z][a-zA-Z\s]+)\s+(?:VIC|NSW|QLD|SA|WA|TAS|ACT|NT),?\s+\d{4}/);
  if (suburbMatch) suburb = suburbMatch[1].trim();

  // Order total — last "Total $xxx.xx"
  let total = 0;
  const totalMatches = [...clean.matchAll(/Total\s+\$?([\d,]+\.?\d*)/gi)];
  if (totalMatches.length > 0) total = parseFloat(totalMatches[totalMatches.length-1][1].replace(',',''));

  // Line items — "Product Name 350ml  12  $3.50  $42.00"
  const items = [];
  const seen = new Set();
  const itemRe = /([A-Z][A-Za-z\s]+(?:350ml|1L|1l|Tea|500ml|200ml)[^\n$]*?)\s+(\d+)\s+\$[\d.]+\s+\$([\d.]+)/g;
  let m;
  while ((m = itemRe.exec(clean)) !== null) {
    const name = m[1].trim().replace(/\s+/g,' ');
    const qty = parseInt(m[2]);
    const lineTotal = parseFloat(m[3]);
    const key = name.toLowerCase();
    if (!seen.has(key) && qty > 0 && name.length > 3) {
      seen.add(key);
      // Strip any table header junk that may prefix the first item name
      const cleanName = name.replace(/^.*?(?=(?:[A-Z][a-z]+\s)+(?:350ml|1L|1l|Tea|500ml|200ml))/,'').trim() || name;
      items.push({ qty, name: cleanName, price: lineTotal > 0 ? +(lineTotal/qty).toFixed(2) : null });
    }
  }

  return {
    orderNumber, customer, dueDate, total,
    items: items.length > 0 ? items : [{ qty: 0, name: 'See Ordermentum for details', price: null }],
    paymentMethod: '', status: 'Order Confirmed', source: 'email',
    courier: '', suburb, state
  };
}

// ── POD email parser ────────────────────────────────────────────
function parsePODEmail(subject, bodyText) {
  // Must contain OMO reference
  const omoMatch = (bodyText + ' ' + subject).match(/OMO\d+/g);
  if (!omoMatch) return null;
  // POD emails typically come from couriers — subject contains "delivery", "delivered", "POD", "proof"
  const isPOD = /\b(delivered|delivery confirmation|proof of delivery|POD|signed|completed)\b/i.test(subject + ' ' + bodyText);
  if (!isPOD) return null;
  return [...new Set(omoMatch)]; // unique OMO numbers
}

// ── Poll inbox — orders + PODs ──────────────────────────────────
const MAILBOX = 'admin@pressedjuices.com.au';
const MSG_ENDPOINT = `https://graph.microsoft.com/v1.0/users/${MAILBOX}/messages`;
async function pollInbox() {
  try {
    const accessToken = await getAccessToken();
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const filter = encodeURIComponent(`isRead eq false and receivedDateTime ge ${since}`);
    const resp = await fetch(
      `${MSG_ENDPOINT}?$filter=${filter}&$select=id,subject,body,from,receivedDateTime&$top=50`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const data = await resp.json();
    if (!data.value?.length) return;

    let ordersAdded = 0, podsUpdated = 0;

    for (const msg of data.value) {
      // Skip already processed
      const already = await db(`SELECT 1 FROM processed_emails WHERE message_id = $1`, [msg.id]);
      if (already.rows.length > 0) continue;

      const fromAddr = msg.from?.emailAddress?.address || '';
      const subject  = msg.subject || '';
      const bodyText = msg.body?.content?.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ') || '';

      // ── POD emails (from couriers — check first) ──────────────
      const podOrders = parsePODEmail(subject, bodyText);
      if (podOrders) {
        // Fetch attachments for this message
        let podFilename = null, podData = null, podContentType = null;
        try {
          const attResp = await fetch(
            `${MSG_ENDPOINT}/${msg.id}/attachments?$select=id,name,contentType,contentBytes`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
          );
          const attData = await attResp.json();
          const pdfAtt = attData.value?.find(a =>
            a.contentType === 'application/pdf' || a.name?.toLowerCase().endsWith('.pdf')
          );
          if (pdfAtt) {
            podFilename = pdfAtt.name;
            podData = pdfAtt.contentBytes; // already base64 from Graph
            podContentType = pdfAtt.contentType || 'application/pdf';
          }
        } catch (e) { console.error('Attachment fetch error:', e.message); }

        const stored = await db(`SELECT value FROM kv_store WHERE key = 'ws-orders'`);
        const orders = stored.rows.length > 0 ? (stored.rows[0].value || []) : [];
        let changed = false;
        const deliveredAt = new Date().toLocaleString('en-AU');
        const updated = orders.map(o => {
          if (podOrders.includes(o.orderNumber) && o.status !== 'Delivered') {
            changed = true;
            podsUpdated++;
            console.log(`📦 POD: ${o.orderNumber} → Delivered${podFilename ? ` (${podFilename})` : ''}`);
            return { ...o, status: 'Delivered', deliveredAt, podFile: podFilename || null };
          }
          return o;
        });
        if (changed) {
          await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ('ws-orders', $1, NOW())
                    ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
                    [JSON.stringify(updated)]);
          // Store PDF attachment per order number
          if (podData) {
            for (const oNum of podOrders) {
              await db(`INSERT INTO pod_attachments (order_number, filename, content_type, data, received_at)
                        VALUES ($1, $2, $3, $4, NOW())
                        ON CONFLICT (order_number) DO UPDATE SET filename=$2, content_type=$3, data=$4, received_at=NOW()`,
                        [oNum, podFilename, podContentType, podData]).catch(e => console.error('POD store error:', e.message));
            }
          }
        }
      }

      // ── Ordermentum order emails ───────────────────────────────
      const isOrdermentum = fromAddr.includes('ordermentum') ||
                            subject.toLowerCase().includes('ordermentum') ||
                            /OMO\d+/.test(subject);
      if (isOrdermentum && !podOrders) {
        const order = parseOrdermentumEmail(subject, bodyText);
        if (order) {
          const stored = await db(`SELECT value FROM kv_store WHERE key = 'ws-orders'`);
          const orders = stored.rows.length > 0 ? (stored.rows[0].value || []) : [];
          if (!orders.find(o => o.orderNumber === order.orderNumber)) {
            orders.unshift(order);
            await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ('ws-orders', $1, NOW())
                      ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
                      [JSON.stringify(orders)]);
            ordersAdded++;
            console.log(`📬 New order: ${order.orderNumber} — ${order.customer}`);
          }
        }
      }

      // Mark read + record processed
      await fetch(`${MSG_ENDPOINT}/${msg.id}`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ isRead: true })
      });
      await db(`INSERT INTO processed_emails (message_id) VALUES ($1) ON CONFLICT DO NOTHING`, [msg.id]);
    }

    if (ordersAdded > 0 || podsUpdated > 0)
      console.log(`✅ Poll: ${ordersAdded} new order(s), ${podsUpdated} POD(s) delivered`);
  } catch (e) {
    if (e.message !== 'Graph not connected') console.error('Poll error:', e.message);
  }
}

// ── POD attachment storage ──────────────────────────────────────
async function initAttachmentsTable() {
  await db(`
    CREATE TABLE IF NOT EXISTS pod_attachments (
      order_number TEXT PRIMARY KEY,
      filename TEXT,
      content_type TEXT,
      data TEXT,
      received_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

app.get('/api/pod/:orderNumber', auth, async (req, res) => {
  try {
    const result = await db(`SELECT filename, content_type, data FROM pod_attachments WHERE order_number = $1`, [req.params.orderNumber]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'No POD found' });
    const { filename, content_type, data } = result.rows[0];
    const buffer = Buffer.from(data, 'base64');
    res.setHeader('Content-Type', content_type || 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    res.send(buffer);
  } catch (e) { res.status(500).json({ error: e.message }); }
});


app.post('/api/graph/poll', auth, async (req, res) => {
  try { await pollInbox(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Poll every 3 minutes
cron.schedule('*/3 * * * *', pollInbox);

// ── Serve frontend ──────────────────────────────────────────────
app.use(express.static(join(__dirname, 'public')));

app.get('*', (req, res) => {
  const p = join(__dirname, 'public', 'index.html');
  existsSync(p) ? res.sendFile(p) : res.send('<h2>Add index.html to /public</h2>');
});

// ── Boot ────────────────────────────────────────────────────────
initDB().then(async () => {
  await initAttachmentsTable();
  app.listen(PORT, () => console.log(`🚀 Wholesale State on port ${PORT}`));
  // Poll on startup
  setTimeout(pollInbox, 5000);
}).catch(e => { console.error('Startup failed:', e); process.exit(1); });
