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
import { promisify } from 'util';
import { readFile as _readFile, writeFile as _writeFile, mkdir as _mkdir } from 'fs/promises';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(join(__dirname, 'public')));

// ── Ensure openpyxl is installed ─────────────────────────────────
import { exec as _execSync } from 'child_process';
_execSync('python3 -c "import openpyxl" 2>/dev/null || pip3 install openpyxl --break-system-packages -q 2>/dev/null || true', (e)=>{
  if(!e) console.log('✅ openpyxl ready');
  else {
    _execSync('pip install openpyxl --break-system-packages -q', ()=>{});
  }
});

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
    let value = req.body.value;

    // ── When ws-orders is saved, merge CSV data into any email-sourced orders ──
    // The frontend sends the full orders array; we enrich email orders with CSV fields
    if (req.params.key === 'ws-orders' && Array.isArray(value)) {
      value = value.map(order => {
        // Only enrich email-sourced orders that are missing CSV fields
        if (order.source !== 'email') return order;
        // CSV fields that email can't provide: courier, accountManager, csvItems, etc.
        // These are passed in by the frontend when it merges — just preserve them
        return order;
      });
    }

    await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ($1, $2, NOW())
              ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=NOW()`,
              [req.params.key, JSON.stringify(value)]);
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
// Parses the structured Ordermentum invoice text (email body = PDF text content)
// Format is line-by-line structured: "FIELD VALUE" or "FIELD\nVALUE on next line"
function parseOrdermentumEmail(subject, bodyText, receivedDateTime) {
  // Must contain an OMO/OMI number somewhere
  const omoMatch = (bodyText + ' ' + subject).match(/OMO\d+/);
  const omiMatch = (bodyText + ' ' + subject).match(/OMI(\d+)/);
  if (!omoMatch && !omiMatch) return null;

  const lines = bodyText.split('\n').map(l => l.trim()).filter(l => l.length > 0);

  // ── Extract all labelled fields anywhere in the doc ──
  const field = (label) => {
    const re = new RegExp(label + '\\s+(.+)', 'i');
    for (const l of lines) { const m = l.match(re); if (m) return m[1].trim(); }
    return null;
  };

  let orderNumber  = field('ORDER NUMBER')  || (omoMatch ? omoMatch[0] : null);
  let invoiceNumber= field('INVOICE NUMBER')|| (omiMatch ? 'OMI'+omiMatch[1] : null);
  let invoiceDate  = field('INVOICE DATE');
  let deliveryDate = field('DELIVERY DATE');
  let dueDate      = field('DUE DATE');
  let paymentStatus= field('PAYMENT STATUS');

  // Normalise date from Ordermentum format (DD/MM/YYYY already, or MM/DD/YYYY — detect)
  const normDate = (s) => {
    if (!s) return '';
    // Already DD/MM/YYYY
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) return s;
    // Try to parse and reformat
    const d = new Date(s);
    if (!isNaN(d)) {
      return String(d.getDate()).padStart(2,'0') + '/' + String(d.getMonth()+1).padStart(2,'0') + '/' + d.getFullYear();
    }
    return s;
  };

  // ── TO block: customer name + address ──
  let customer = null, address = null, suburb = null, state = null, postcode = null;
  const toIdx = lines.findIndex(l => /^TO$/i.test(l));
  if (toIdx >= 0) {
    let i = toIdx + 1;
    // Skip any line that is a known header/label
    const isLabel = l => /^(FROM|INVOICE|ORDER|DELIVERY|DUE|PAYMENT|ITEM|Subtotal|Total|Freight|GST)/i.test(l);
    if (i < lines.length && !isLabel(lines[i])) {
      customer = lines[i].trim(); i++;
    }
    // Address line — first non-label line after customer that isn't suburb/state
    if (i < lines.length && !isLabel(lines[i]) && !/^\d{4}$/.test(lines[i])) {
      // Could be "382, Little Collins St" or "382 Little Collins St"
      if (/^\d/.test(lines[i]) || /^[A-Z]/.test(lines[i])) {
        address = lines[i].trim(); i++;
      }
    }
    // Suburb, STATE, postcode line
    if (i < lines.length) {
      const locMatch = lines[i].match(/^(.+?)[,\s]+(VIC|NSW|QLD|SA|WA|TAS|ACT|NT)[,\s]+(\d{4})/i);
      if (locMatch) {
        suburb   = locMatch[1].trim().replace(/,$/, '');
        state    = locMatch[2].trim().toUpperCase();
        postcode = locMatch[3].trim();
        i++;
      }
    }
  }

  // ── Items table ──
  // Header row might appear as "ITEM QTY PRICE SUBTOTAL" all on one line
  const items = [];
  const itemHeaderIdx = lines.findIndex(l => /ITEM\s+QTY\s+PRICE\s+SUBTOTAL/i.test(l));
  if (itemHeaderIdx >= 0) {
    let i = itemHeaderIdx + 1;
    while (i < lines.length) {
      const l = lines[i];
      if (/^ITEM TOTAL|^Subtotal|^Freight|^GST|^Total|^Surcharge|^How to pay/i.test(l)) break;
      // "Roots 350ml 12 $3.30 $39.60" or "Roots 350ml 12 3.30 39.60"
      const im = l.match(/^(.+?)\s+(\d+)\s+\$?([\d.]+)\s+\$?([\d.]+)$/);
      if (im) {
        items.push({ name: im[1].trim(), qty: parseInt(im[2]), price: parseFloat(im[3]) });
      }
      i++;
    }
  }

  // ── Totals ──
  let subtotal = null, grandTotal = null;
  for (const l of lines) {
    const sm = l.match(/^Subtotal\s+\$?([\d,]+\.?\d*)/i);
    if (sm) subtotal = parseFloat(sm[1].replace(',',''));
    const tm = l.match(/^Total\s+\$?([\d,]+\.?\d*)/i);
    if (tm) grandTotal = parseFloat(tm[1].replace(',',''));
  }

  // ── Timestamp from receivedDateTime ──
  let placedAt = null;
  if (receivedDateTime) {
    try {
      const dt = new Date(receivedDateTime);
      const dd = String(dt.getDate()).padStart(2,'0');
      const mm = String(dt.getMonth()+1).padStart(2,'0');
      const yyyy = dt.getFullYear();
      let hrs = dt.getHours(), mins = String(dt.getMinutes()).padStart(2,'0');
      const ampm = hrs >= 12 ? 'pm' : 'am';
      hrs = hrs % 12 || 12;
      placedAt = `${dd}/${mm}/${yyyy}, ${hrs}:${mins} ${ampm}`;
    } catch(e) {}
  }

  if (!orderNumber) return null;

  return {
    orderNumber,
    invoiceNumber:  invoiceNumber || '',
    invoiceDate:    normDate(invoiceDate),
    customer:       customer || 'Unknown',
    address:        address  || '',
    suburb:         suburb   || '',
    state:          state    || '',
    postcode:       postcode || '',
    dueDate:        normDate(deliveryDate || dueDate),  // Delivery Date = when they receive it
    total:          subtotal || grandTotal || 0,
    paymentStatus:  paymentStatus || '',
    placedAt,
    items:          items,
    status:         'Order Confirmed',
    source:         'email',
    courier:        '',   // filled in from CSV
    // CSV-fillable fields (empty until CSV uploaded)
    accountManager: '',
    customergroup:  '',
    label:          '',
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
      // Preserve structure: block-level tags → newlines, then strip remaining HTML
      const rawBody = msg.body?.content || '';
      const bodyText = rawBody
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<\/tr>/gi, '\n')
        .replace(/<\/td>/gi, ' ')
        .replace(/<\/p>/gi, '\n')
        .replace(/<\/div>/gi, '\n')
        .replace(/<\/li>/gi, '\n')
        .replace(/<[^>]+>/g, '')
        .replace(/&amp;/g,'&').replace(/&nbsp;/g,' ').replace(/&#39;/g,"'").replace(/&rsquo;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>')
        .split('\n').map(l => l.replace(/\s+/g,' ').trim()).filter(l => l.length > 0).join('\n');

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
        const order = parseOrdermentumEmail(subject, bodyText, msg.receivedDateTime);
        if (order) {
          const stored = await db(`SELECT value FROM kv_store WHERE key = 'ws-orders'`);
          const orders = stored.rows.length > 0 ? (stored.rows[0].value || []) : [];
          const existing = orders.find(o => o.orderNumber === order.orderNumber);
          if (!existing) {
            // New order — insert at top
            orders.unshift(order);
            await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ('ws-orders', $1, NOW())
                      ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
                      [JSON.stringify(orders)]);
            ordersAdded++;
            console.log(`📬 New order: ${order.orderNumber} — ${order.customer}`);
          } else {
            // Existing order — enrich with any new fields from this email parse
            let changed = false;
            const enrichFields = ['customer','address','suburb','state','postcode','dueDate','invoiceDate','placedAt','total','paymentStatus','invoiceNumber','items'];
            for (const f of enrichFields) {
              const val = order[f];
              const isEmpty = v => v === undefined || v === null || v === '' || v === 'Unknown' || (Array.isArray(v) && v.length === 0);
              if (!isEmpty(val) && isEmpty(existing[f])) {
                existing[f] = val;
                changed = true;
              }
            }
            if (changed) {
              const idx = orders.findIndex(o => o.orderNumber === order.orderNumber);
              orders[idx] = existing;
              await db(`INSERT INTO kv_store (key, value, updated_at) VALUES ('ws-orders', $1, NOW())
                        ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
                        [JSON.stringify(orders)]);
              console.log(`📬 Enriched order: ${order.orderNumber}`);
            }
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


app.post('/api/clear-processed', auth, async (req, res) => {
  try {
    await db(`DELETE FROM processed_emails`);
    res.json({ ok: true, message: 'Processed emails cleared — next poll will re-parse all emails' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/graph/poll', auth, async (req, res) => {
  try { await pollInbox(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Poll every 3 minutes
cron.schedule('*/3 * * * *', pollInbox);


// ── File Generation (Python + openpyxl) ────────────────────────
const execAsync = promisify(_execSync);

const TPL_DIR = join(process.cwd(), 'templates');

const GEN_SCRIPT = `import csv, shutil, math, datetime, zipfile, json, sys, os
from collections import defaultdict
from openpyxl import load_workbook, Workbook
from openpyxl.styles import Font, PatternFill, Alignment

CSV_PATH = sys.argv[1] if len(sys.argv) > 1 else '/mnt/user-data/uploads/ORDER_ITEMS_MASTER_SHEET.csv'
OUT_DIR  = sys.argv[2] if len(sys.argv) > 2 else '/tmp/gen_out'
DATE_STR = sys.argv[3] if len(sys.argv) > 3 else datetime.date.today().strftime('%d-%m-%Y')
GEN_TYPE = sys.argv[4] if len(sys.argv) > 4 else 'all'
TPL_DIR  = sys.argv[5] if len(sys.argv) > 5 else '/mnt/user-data/uploads'

os.makedirs(OUT_DIR, exist_ok=True)

with open(CSV_PATH, newline='', encoding='utf-8-sig') as f:
    ALL = list(csv.DictReader(f))
rows = [r for r in ALL if r.get('SKU','') != 'FREIGHT']
today = datetime.date.today().strftime('%d/%m/%Y')

by_order = defaultdict(list)
for r in rows:
    by_order[r['OrderNumber']].append(r)

def total_cartons(ords):
    t = 0
    for r in ords:
        p = r.get('Product',''); qty = int(r.get('Quantity',0) or 0)
        if p=='350': t += math.ceil(qty/24)
        elif p=='TEA': t += math.ceil(qty/18)
        elif p=='1L': t += math.ceil(qty/12)
    return t

def inv_value(ords):
    return sum(float(r.get('UnitPrice',0) or 0)*int(r.get('Quantity',0) or 0) for r in ords if r.get('Product'))

def courier_orders(courier):
    return {k:v for k,v in by_order.items() if v[0].get('Courier','')==courier}

GREY = PatternFill('solid', fgColor='D3D3D3')
BOLD = Font(bold=True, name='Calibri', size=11)
generated = []

# ══════════════════════════════════════════════
# 1. COLDXPRESS
# ══════════════════════════════════════════════
if GEN_TYPE in ('coldxpress','all'):
    src = f'{TPL_DIR}/COLDXPRESS.xlsx'
    dst = f'{OUT_DIR}/{DATE_STR}_COLDXPRESS.xlsx'
    shutil.copy(src, dst)
    wb = load_workbook(dst)
    ws = wb.active
    ws['B4'] = today
    cx = courier_orders('COLDXPRESS')
    for ri, onum in enumerate(sorted(cx.keys()), 6):
        ords = cx[onum]; r0 = ords[0]
        ws.cell(ri,1).value = onum
        ws.cell(ri,2).value = r0.get('DueDate','')
        ws.cell(ri,4).value = r0.get('Customer','')
        ws.cell(ri,5).value = r0.get('CustomerAddress1','')
        ws.cell(ri,6).value = r0.get('CustomerSuburb','')
        ws.cell(ri,7).value = r0.get('CustomerState','')
        try: ws.cell(ri,8).value = int(r0.get('Postcode',0))
        except: ws.cell(ri,8).value = r0.get('Postcode','')
        ws.cell(ri,9).value  = total_cartons(ords)
        ws.cell(ri,12).value = round(inv_value(ords),2)
        ws.cell(ri,14).value = 'chilled'
        ws.cell(ri,15).value = r0.get('Notes','')
    wb.save(dst); generated.append(dst)
    print(f'✅ COLDXPRESS — {len(cx)} orders', file=sys.stderr)

# ══════════════════════════════════════════════
# 2. DK DISTRIBUTIONS
# ══════════════════════════════════════════════
if GEN_TYPE in ('dk','all'):
    src = f'{TPL_DIR}/DK_DISTRIBUTIONS.xlsx'
    dst = f'{OUT_DIR}/{DATE_STR}_DK_DISTRIBUTIONS.xlsx'
    shutil.copy(src, dst)
    wb = load_workbook(dst)
    ws = wb['jobs']
    dk = courier_orders('DKDISTRIBUTION')
    for ri, onum in enumerate(sorted(dk.keys()), 2):
        ords = dk[onum]; r0 = ords[0]
        ws.cell(ri,1).value  = onum
        ws.cell(ri,2).value  = today
        ws.cell(ri,3).value  = 'Business'
        ws.cell(ri,4).value  = r0.get('Customer','')
        ws.cell(ri,5).value  = r0.get('CustomerAddress1','')
        ws.cell(ri,6).value  = r0.get('CustomerAddress2','')
        try: ws.cell(ri,8).value = int(r0.get('Postcode',0))
        except: ws.cell(ri,8).value = r0.get('Postcode','')
        ws.cell(ri,9).value  = r0.get('CustomerSuburb','')
        ws.cell(ri,10).value = r0.get('CustomerState','')
        ws.cell(ri,15).value = r0.get('Notes','')
        ws.cell(ri,17).value = 'WS'
        ws.cell(ri,18).value = total_cartons(ords)
    wb.save(dst); generated.append(dst)
    print(f'✅ DK_DISTRIBUTIONS — {len(dk)} orders', file=sys.stderr)

# ══════════════════════════════════════════════
# 3. COOLCOURIERS
# ══════════════════════════════════════════════
if GEN_TYPE in ('coolcouriers','all'):
    src = f'{TPL_DIR}/COOLCOURIERS.xlsx'
    dst = f'{OUT_DIR}/{DATE_STR}_COOLCOURIERS.xlsx'
    shutil.copy(src, dst)
    wb = load_workbook(dst)
    ws = wb['jobs']
    cc = courier_orders('COOLCOURIERS')
    for ri, onum in enumerate(sorted(cc.keys()), 2):
        ords = cc[onum]; r0 = ords[0]
        ws.cell(ri,1).value  = onum
        ws.cell(ri,2).value  = today
        ws.cell(ri,3).value  = 'Business'
        ws.cell(ri,4).value  = r0.get('Customer','')
        ws.cell(ri,5).value  = r0.get('CustomerAddress1','')
        ws.cell(ri,6).value  = r0.get('CustomerAddress2','')
        try: ws.cell(ri,7).value = int(r0.get('Postcode',0))
        except: ws.cell(ri,7).value = r0.get('Postcode','')
        ws.cell(ri,8).value  = r0.get('CustomerSuburb','')
        ws.cell(ri,9).value  = r0.get('CustomerState','')
        ws.cell(ri,10).value = r0.get('Notes','')
        ws.cell(ri,11).value = 'WS'
        ws.cell(ri,12).value = total_cartons(ords)
    wb.save(dst); generated.append(dst)
    print(f'✅ COOLCOURIERS — {len(cc)} orders', file=sys.stderr)

# ══════════════════════════════════════════════
# 4. PRODUCTION SHEET
# Uses insert_rows() to make space — handles any volume
# ══════════════════════════════════════════════
if GEN_TYPE in ('production','all'):
    src = f'{TPL_DIR}/Production_Sheet.xlsx'
    dst = f'{OUT_DIR}/{DATE_STR}_Production_Sheet.xlsx'
    shutil.copy(src, dst)
    wb = load_workbook(dst)
    ws = wb['Sheet1']

    # Update date row 1
    from datetime import date as _date
    d = _date.today()
    suffix = 'th' if 11<=d.day<=13 else {1:'st',2:'nd',3:'rd'}.get(d.day%10,'th')
    ws.cell(1,1).value = f"{d.strftime('%A')} - {d.day}{suffix} {d.strftime('%B %Y')}"

    SKUS_350 = ['Antiox 350ml','Blueberry Glow 350ml','Botanical 350ml','Cloudy Apple 350ml',
                'Energise 350ml','Immunity 350ml','Pure Orange 350ml','Refresh 350ml',
                'Roots 350ml','Tropical Bliss 350ml']
    SKUS_TEA = ['Organic Lemon Iced Tea 350ml','Organic Peach Iced Tea 350ml','Organic Raspberry Iced Tea 350ml']
    SKUS_1L  = ['Botanical 1L','Immunity 1L','Tropical Bliss 1L']

    def build_section_rows(skus, product_filter):
        """Build list of row dicts for this product section — couriers sorted, with subtotals + grand total."""
        couriers_data = defaultdict(list)
        for onum, ords in sorted(by_order.items()):
            pr = [r for r in ords if r.get('Product') == product_filter]
            if not pr: continue
            r0 = ords[0]
            sq = defaultdict(int)
            for r in pr: sq[r['Name']] += int(r.get('Quantity', 0) or 0)
            total_qty = sum(sq.values())
            tot_crt = math.ceil(total_qty / (24 if product_filter=='350' else 18 if product_filter=='TEA' else 12))
            couriers_data[r0.get('Courier','')].append({
                'courier': r0.get('Courier',''), 'onum': onum,
                'cid': r0.get('CustomerId',''), 'cust': r0.get('Customer',''),
                'sq': dict(sq), 'tq': total_qty, 'tc': tot_crt
            })

        out_rows = []  # list of (is_subtotal, is_grandtotal, data_dict)
        grand_totals = defaultdict(int)
        grand_cartons = 0

        for courier in sorted(couriers_data.keys()):
            items = couriers_data[courier]
            cst = defaultdict(int); cqt = 0; cct = 0
            for it in items:
                out_rows.append(('data', it))
                for sku in skus: cst[sku] += it['sq'].get(sku, 0); grand_totals[sku] += it['sq'].get(sku, 0)
                cqt += it['tq']; cct += it['tc']; grand_cartons += it['tc']
            out_rows.append(('subtotal', {'courier': courier, 'cst': dict(cst), 'cqt': cqt, 'cct': cct}))

        out_rows.append(('grandtotal', {'grand_totals': dict(grand_totals), 'grand_cartons': grand_cartons}))
        return out_rows

    def write_section(ws, hrow, skus, product_filter):
        """
        Find existing data rows between hrow+1 and Discrepancies row.
        Delete them all, insert exactly as many as needed, then write data.
        This handles any volume correctly.
        """
        # Find the Discrepancies row for THIS section (first one after hrow)
        disc_row = None
        for r in range(hrow + 1, ws.max_row + 2):
            v = ws.cell(r, 1).value
            if v == 'Discrepancies:':
                disc_row = r; break

        if disc_row is None:
            print(f'  WARNING: no Discrepancies row found after row {hrow}', file=sys.stderr)
            return

        # Build the data we need to write
        section_rows = build_section_rows(skus, product_filter)
        rows_needed = len(section_rows)

        # How many data rows exist currently between header and Discrepancies?
        existing_data_rows = disc_row - hrow - 1  # rows hrow+1 .. disc_row-1

        print(f'  Section at row {hrow}: {existing_data_rows} existing rows, need {rows_needed}', file=sys.stderr)

        if rows_needed > existing_data_rows:
            # Need to insert rows — insert at disc_row to push Discrepancies (and everything below) down
            insert_count = rows_needed - existing_data_rows
            ws.insert_rows(disc_row, insert_count)
            print(f'  Inserted {insert_count} rows before row {disc_row}', file=sys.stderr)
            disc_row += insert_count  # disc_row has moved down
        elif rows_needed < existing_data_rows:
            # Delete surplus rows
            delete_count = existing_data_rows - rows_needed
            ws.delete_rows(hrow + 1, delete_count)
            print(f'  Deleted {delete_count} surplus rows', file=sys.stderr)
            disc_row -= delete_count

        # Now write exactly rows_needed rows starting at hrow+1
        for i, (rtype, rdata) in enumerate(section_rows):
            r = hrow + 1 + i
            # Clear the row first
            for c in range(1, 17): ws.cell(r, c).value = None

            if rtype == 'data':
                ws.cell(r, 1).value = rdata['courier']
                ws.cell(r, 2).value = rdata['onum']
                ws.cell(r, 3).value = rdata['cid']
                ws.cell(r, 4).value = rdata['cust']
                for ci, sku in enumerate(skus, 5):
                    q = rdata['sq'].get(sku, 0)
                    if q: ws.cell(r, ci).value = q
                ws.cell(r, 5 + len(skus)).value = rdata['tq']
                ws.cell(r, 6 + len(skus)).value = rdata['tc']

            elif rtype == 'subtotal':
                ws.cell(r, 4).value = 'Total'; ws.cell(r, 4).font = BOLD
                for ci, sku in enumerate(skus, 5):
                    v = rdata['cst'].get(sku, 0)
                    if v: ws.cell(r, ci).value = v; ws.cell(r, ci).font = BOLD
                ws.cell(r, 5 + len(skus)).value = rdata['cqt']; ws.cell(r, 5 + len(skus)).font = BOLD
                ws.cell(r, 6 + len(skus)).value = rdata['cct']; ws.cell(r, 6 + len(skus)).font = BOLD

            elif rtype == 'grandtotal':
                ws.cell(r, 4).value = 'Grand Total'; ws.cell(r, 4).font = BOLD; ws.cell(r, 4).fill = GREY
                for ci, sku in enumerate(skus, 5):
                    v = rdata['grand_totals'].get(sku, 0)
                    if v: ws.cell(r, ci).value = v; ws.cell(r, ci).font = BOLD; ws.cell(r, ci).fill = GREY
                gt = sum(rdata['grand_totals'].values())
                ws.cell(r, 5 + len(skus)).value = gt; ws.cell(r, 5 + len(skus)).font = BOLD; ws.cell(r, 5 + len(skus)).fill = GREY
                ws.cell(r, 6 + len(skus)).value = rdata['grand_cartons']; ws.cell(r, 6 + len(skus)).font = BOLD; ws.cell(r, 6 + len(skus)).fill = GREY

    # Find section headers dynamically
    courier_rows = []
    for row in ws.iter_rows(min_row=1, max_row=ws.max_row):
        if row[0].value == 'Courier': courier_rows.append(row[0].row)

    if len(courier_rows) >= 3:
        # Write sections in REVERSE order so insert_rows doesn't shift subsequent section positions
        write_section(ws, courier_rows[2], SKUS_1L,  '1L')
        write_section(ws, courier_rows[1], SKUS_TEA, 'TEA')
        write_section(ws, courier_rows[0], SKUS_350, '350')
    else:
        print(f'  ERROR: only found {len(courier_rows)} Courier header rows', file=sys.stderr)

    wb.save(dst); generated.append(dst)
    print(f'✅ Production_Sheet', file=sys.stderr)

# ══════════════════════════════════════════════
# 5 & 6. PRINT FILES — clone templates, write only cols A,C,D,E,F
#         Col B has formulas — DO NOT TOUCH
#         Use insert_rows to handle any volume
# ══════════════════════════════════════════════
if GEN_TYPE in ('prints','all'):
    sr = sorted(rows, key=lambda r:(r.get('Courier',''),r.get('Customer',''),r.get('OrderNumber',''),r.get('SKU','')))
    r350 = [r for r in sr if r.get('Product')=='350']
    rtea = [r for r in sr if r.get('Product')=='TEA']
    r1l  = [r for r in sr if r.get('Product')=='1L']

    def write_print(tpl_name, sheet_name, data_rows, is_backs):
        src = f'{TPL_DIR}/{tpl_name}'
        dst = f'{OUT_DIR}/{DATE_STR}_{tpl_name}'
        shutil.copy(src, dst)
        wb = load_workbook(dst)
        ws = wb[sheet_name]

        copies_blank = 24 if '350' in tpl_name else 18 if 'Tea' in tpl_name else 12

        # How many data rows currently exist (row 2 onwards, before the final blank row)
        # Template has: row1=headers, row2=top BLANK, rows 3..N-1=data, rowN=bottom BLANK
        existing_total = ws.max_row - 1  # excluding header row 1
        # We need: 1 top blank + len(data_rows) data rows + 1 bottom blank
        rows_needed = len(data_rows) + 2

        if rows_needed > existing_total:
            # Insert rows after row 2 (after top blank), pushing everything down
            insert_count = rows_needed - existing_total
            ws.insert_rows(3, insert_count)
            print(f'  {tpl_name}: inserted {insert_count} rows ({existing_total}→{rows_needed})', file=sys.stderr)
        elif rows_needed < existing_total:
            delete_count = existing_total - rows_needed
            ws.delete_rows(3, delete_count)
            print(f'  {tpl_name}: deleted {delete_count} rows ({existing_total}→{rows_needed})', file=sys.stderr)

        # Clear all data cols (not col B — formula) from row 2 to end
        for r in range(2, ws.max_row + 1):
            for c in [1, 3, 4, 5, 6]:
                ws.cell(r, c).value = None

        if is_backs:
            n = rows_needed
            # Top blank
            ws.cell(2,1).value=n; ws.cell(2,3).value='BLANK'; ws.cell(2,4).value=copies_blank; ws.cell(2,5).value=''; ws.cell(2,6).value='BLANK'; n-=1
            # Data rows
            for di, r in enumerate(data_rows, 3):
                bl = r.get('BackLabels','BACKS')
                ws.cell(di,1).value=n; ws.cell(di,3).value=r['SKU']
                ws.cell(di,4).value=int(r.get('Quantity',0) or 0)
                ws.cell(di,5).value=r.get('Customer',''); ws.cell(di,6).value=bl; n-=1
            # Bottom blank
            last = 2 + len(data_rows) + 1
            ws.cell(last,1).value=n; ws.cell(last,3).value='BLANK'; ws.cell(last,4).value=copies_blank; ws.cell(last,5).value=''; ws.cell(last,6).value='BLANK'
        else:
            n = 1
            # Top blank
            ws.cell(2,1).value=n; ws.cell(2,3).value='BLANK'; ws.cell(2,4).value=copies_blank; ws.cell(2,5).value=''; ws.cell(2,6).value='BLANK'; n+=1
            # Data rows
            for di, r in enumerate(data_rows, 3):
                ws.cell(di,1).value=n; ws.cell(di,3).value=r['SKU']
                ws.cell(di,4).value=int(r.get('Quantity',0) or 0)
                ws.cell(di,5).value=r.get('Customer',''); ws.cell(di,6).value=r.get('CustomerId',''); n+=1
            # Bottom blank
            last = 2 + len(data_rows) + 1
            ws.cell(last,1).value=n; ws.cell(last,3).value='BLANK'; ws.cell(last,4).value=copies_blank; ws.cell(last,5).value=''; ws.cell(last,6).value='BLANK'

        wb.save(dst); generated.append(dst)
        print(f'✅ {tpl_name} — {len(data_rows)} lines', file=sys.stderr)

    write_print('350ml_Fronts.xlsx', 'FRONTS', r350, False)
    write_print('350ml_Backs.xlsx',  'BACKS',  r350, True)
    write_print('Tea_Fronts.xlsx',   'FRONTS', rtea, False)
    write_print('Tea_Backs.xlsx',    'BACKS',  rtea, True)
    write_print('1L_Fronts.xlsx',    'FRONTS', r1l,  False)

# ══════════════════════════════════════════════
# ZIP
# ══════════════════════════════════════════════
if GEN_TYPE == 'all':
    zip_path = f'{OUT_DIR}/{DATE_STR}_Wholesale_State_Files.zip'
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as z:
        for fp in generated: z.write(fp, os.path.basename(fp))
    print(json.dumps({'zip': zip_path, 'files': [os.path.basename(f) for f in generated]}))
else:
    print(json.dumps({'files': [os.path.basename(f) for f in generated], 'paths': generated}))
`;

app.post('/api/generate', auth, async (req, res) => {
  try {
    const { csvData, type, dateStr } = req.body;
    if (!csvData) return res.status(400).json({ error: 'No CSV data' });

    const tmpDir = '/tmp/ws_gen_' + Date.now();
    const outDir = '/tmp/ws_out_' + Date.now();
    await _mkdir(tmpDir, { recursive: true });
    await _mkdir(outDir, { recursive: true });

    const csvPath = tmpDir + '/orders.csv';
    const pyPath  = tmpDir + '/gen.py';
    const d = (dateStr || new Date().toLocaleDateString('en-AU')).replace(/\//g, '-');

    // csvData may be JSON array of row objects OR actual CSV text
    let csvText = csvData;
    if (csvData.trim().startsWith('[')) {
      // Convert JSON rows array to CSV
      const rowsArr = JSON.parse(csvData);
      if (rowsArr.length > 0) {
        const headers = Object.keys(rowsArr[0]);
        const esc = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
        csvText = [headers.join(','), ...rowsArr.map(r => headers.map(h => esc(r[h])).join(','))].join('\n');
      }
    }
    await _writeFile(csvPath, csvText);
    await _writeFile(pyPath, GEN_SCRIPT);

    const tplDir = existsSync(TPL_DIR) ? TPL_DIR : join(process.cwd(), 'public');
    const cmd = `python3 "${pyPath}" "${csvPath}" "${outDir}" "${d}" "${type}" "${tplDir}"`;
    const { stdout, stderr } = await execAsync(cmd, { timeout: 60000 });

    console.log('Generate log:', stderr.slice(0, 500));
    if (!stdout.trim()) throw new Error('Generator produced no output. ' + stderr.slice(0, 300));

    const result = JSON.parse(stdout.trim());

    if (type === 'all' && result.zip) {
      const zipData = await _readFile(result.zip);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${d}_Wholesale_State_Files.zip"`);
      return res.send(zipData);
    }
    if (result.paths && result.paths.length > 0) {
      const fileData = await _readFile(result.paths[0]);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="${result.files[0]}"`);
      return res.send(fileData);
    }
    res.status(500).json({ error: 'No files generated', detail: stderr });
  } catch(e) {
    console.error('Generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/templates', auth, async (req, res) => {
  try {
    const { filename, data } = req.body;
    if (!filename || !data) return res.status(400).json({ error: 'Missing filename or data' });
    await _mkdir(TPL_DIR, { recursive: true });
    await _writeFile(join(TPL_DIR, filename), Buffer.from(data, 'base64'));
    res.json({ ok: true, filename });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/templates', auth, async (req, res) => {
  try {
    const files = existsSync(TPL_DIR) ? await _readdir(TPL_DIR) : [];
    res.json({ files });
  } catch(e) { res.json({ files: [] }); }
});

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
