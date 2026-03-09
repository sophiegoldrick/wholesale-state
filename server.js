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
import { exec as _exec } from 'child_process';
import { promisify } from 'util';
import { readFile as _readFile, writeFile as _writeFile, mkdir as _mkdir } from 'fs/promises';
const execAsync = promisify(_exec);

app.post('/api/generate', auth, async (req, res) => {
  try {
    const { csvData, type, dateStr } = req.body;
    if (!csvData) return res.status(400).json({ error: 'No CSV data' });

    const tmpDir = '/tmp/ws_gen';
    const outDir = '/tmp/ws_out';
    await _mkdir(tmpDir, { recursive: true });
    await _mkdir(outDir, { recursive: true });
    const csvPath = tmpDir + '/orders.csv';
    const pyPath  = tmpDir + '/gen.py';
    const d = (dateStr || new Date().toLocaleDateString('en-AU')).replace(/\//g,'-');
    await _writeFile(csvPath, csvData);

    const py = `
import csv, math, datetime, os, zipfile, json
from collections import defaultdict
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill

CSV_PATH = '${csvPath}'
OUT_DIR  = '${outDir}'
DATE_STR = '${d}'
GEN_TYPE = '${type}'

with open(CSV_PATH, newline='', encoding='utf-8-sig') as f:
    ALL = list(csv.DictReader(f))
rows = [r for r in ALL if r.get('SKU','') != 'FREIGHT']
today = datetime.date.today().strftime('%d/%m/%Y')
by_order = defaultdict(list)
for r in rows:
    by_order[r['OrderNumber']].append(r)

def cartons_for(qty, product):
    if product=='350': return math.ceil(qty/24)
    if product=='TEA': return math.ceil(qty/18)
    if product=='1L':  return math.ceil(qty/12)
    return 0

def total_cartons(ords):
    return sum(cartons_for(int(r.get('Quantity',0)), r.get('Product','')) for r in ords)

def inv_value(ords):
    return sum(float(r.get('UnitPrice',0))*int(r.get('Quantity',0)) for r in ords if r.get('Product'))

def courier_orders(courier):
    return {k:v for k,v in by_order.items() if v[0].get('Courier','')==courier}

GREY = PatternFill('solid', fgColor='D3D3D3')
BOLD = Font(bold=True, name='Calibri', size=11)

def make_wb(headers):
    wb = Workbook(); ws = wb.active
    for ci,h in enumerate(headers,1):
        c=ws.cell(1,ci,h); c.font=BOLD; c.fill=GREY
    return wb, ws

generated = []

if GEN_TYPE in ('coldxpress','all'):
    wb,ws=make_wb(['INV NO.','DELIVERY DATE','STORE NO','STORE NAME','ADDRESS','SUBURB','STATE','POSTCODE','CARTONS','PALLETS','WEIGHT (KG)','INV. VALUE','COD','TEMP','COMMENT'])
    cx=courier_orders('COLDXPRESS')
    for ri,onum in enumerate(sorted(cx.keys()),2):
        ords=cx[onum]; r0=ords[0]
        ws.cell(ri,1).value=onum; ws.cell(ri,2).value=r0.get('DueDate','')
        ws.cell(ri,4).value=r0.get('Customer',''); ws.cell(ri,5).value=r0.get('CustomerAddress1','')
        ws.cell(ri,6).value=r0.get('CustomerSuburb',''); ws.cell(ri,7).value=r0.get('CustomerState','')
        try: ws.cell(ri,8).value=int(r0.get('Postcode',0))
        except: ws.cell(ri,8).value=r0.get('Postcode','')
        ws.cell(ri,9).value=total_cartons(ords); ws.cell(ri,12).value=round(inv_value(ords),2)
        ws.cell(ri,14).value='chilled'; ws.cell(ri,15).value=r0.get('Notes','')
    p=f'{OUT_DIR}/{DATE_STR}_COLDXPRESS.xlsx'; wb.save(p); generated.append(p)

if GEN_TYPE in ('dk','all'):
    wb,ws=make_wb(['Order ID','Date','Order Type','Notes','Address 1','Address 2','Address 3','Postal Code','City','State','Country','Location','Last Name','Phone','Delivery Instructions','Email','GROUP','Volume'])
    dk=courier_orders('DKDISTRIBUTION')
    for ri,onum in enumerate(sorted(dk.keys()),2):
        ords=dk[onum]; r0=ords[0]
        ws.cell(ri,1).value=onum; ws.cell(ri,2).value=today; ws.cell(ri,3).value='Business'
        ws.cell(ri,4).value=r0.get('Customer',''); ws.cell(ri,5).value=r0.get('CustomerAddress1','')
        ws.cell(ri,6).value=r0.get('CustomerAddress2','')
        try: ws.cell(ri,8).value=int(r0.get('Postcode',0))
        except: ws.cell(ri,8).value=r0.get('Postcode','')
        ws.cell(ri,9).value=r0.get('CustomerSuburb',''); ws.cell(ri,10).value=r0.get('CustomerState','')
        ws.cell(ri,15).value=r0.get('Notes',''); ws.cell(ri,17).value='WS'; ws.cell(ri,18).value=total_cartons(ords)
    p=f'{OUT_DIR}/{DATE_STR}_DK_DISTRIBUTIONS.xlsx'; wb.save(p); generated.append(p)

if GEN_TYPE in ('coolcouriers','all'):
    wb,ws=make_wb(['Order ID','Date','Order Type','Customer','Address 1','Address 2','Postcode','Suburb','State','Notes','Group','Cartons'])
    cc=courier_orders('COOLCOURIERS')
    for ri,onum in enumerate(sorted(cc.keys()),2):
        ords=cc[onum]; r0=ords[0]
        ws.cell(ri,1).value=onum; ws.cell(ri,2).value=today; ws.cell(ri,3).value='Business'
        ws.cell(ri,4).value=r0.get('Customer',''); ws.cell(ri,5).value=r0.get('CustomerAddress1','')
        ws.cell(ri,6).value=r0.get('CustomerAddress2','')
        try: ws.cell(ri,7).value=int(r0.get('Postcode',0))
        except: ws.cell(ri,7).value=r0.get('Postcode','')
        ws.cell(ri,8).value=r0.get('CustomerSuburb',''); ws.cell(ri,9).value=r0.get('CustomerState','')
        ws.cell(ri,10).value=r0.get('Notes',''); ws.cell(ri,11).value='WS'; ws.cell(ri,12).value=total_cartons(ords)
    p=f'{OUT_DIR}/{DATE_STR}_COOLCOURIERS.xlsx'; wb.save(p); generated.append(p)

if GEN_TYPE in ('production','all'):
    SKUS_350=['Antiox 350ml','Blueberry Glow 350ml','Botanical 350ml','Cloudy Apple 350ml','Energise 350ml','Immunity 350ml','Pure Orange 350ml','Refresh 350ml','Roots 350ml','Tropical Bliss 350ml']
    SKUS_TEA=['Organic Lemon Iced Tea 350ml','Organic Peach Iced Tea 350ml','Organic Raspberry Iced Tea 350ml']
    SKUS_1L=['Botanical 1L','Immunity 1L','Tropical Bliss 1L']
    wb=Workbook(); ws=wb.active
    def write_section(start_row, skus, pf, label_val, prod_val):
        ws.cell(start_row,1).value=f'{prod_val} Orders'; ws.cell(start_row,1).font=Font(bold=True,name='Calibri',size=16)
        ws.cell(start_row,15).value='LABELS'; ws.cell(start_row,16).value=label_val
        ws.cell(start_row+1,15).value='CUSTOMERGROUP'; ws.cell(start_row+1,16).value='REGULAR'
        ws.cell(start_row+2,1).value='Labelling Date:'; ws.cell(start_row+2,4).value='Staff Working:'
        ws.cell(start_row+2,15).value='PRODUCT'; ws.cell(start_row+2,16).value=prod_val
        ws.cell(start_row+4,4).value='Batch Number:'
        hrow=start_row+5
        hdrs=['Courier','Order Number','Customer ID','Customer']+skus+['Grand Total','Cartons']
        for ci,h in enumerate(hdrs,1): c=ws.cell(hrow,ci,h); c.font=BOLD; c.fill=GREY
        couriers_data=defaultdict(list)
        for onum,ords in sorted(by_order.items()):
            pr=[r for r in ords if r.get('Product')==pf]
            if not pr: continue
            r0=ords[0]; sq={r['Name']:int(r.get('Quantity',0)) for r in pr}
            tq=sum(sq.values()); tc=math.ceil(tq/(24 if pf=='350' else 18 if pf=='TEA' else 12))
            couriers_data[r0.get('Courier','')].append((r0.get('Courier',''),onum,r0.get('CustomerId',''),r0.get('Customer',''),sq,tq,tc))
        dr=hrow+1; gt=defaultdict(int); gc=0
        for cour in sorted(couriers_data.keys()):
            items=couriers_data[cour]; cst=defaultdict(int); cqt=0; cct=0
            for (_,onum,cid,cust,sq,tq,tc) in items:
                ws.cell(dr,1).value=cour; ws.cell(dr,2).value=onum; ws.cell(dr,3).value=cid; ws.cell(dr,4).value=cust
                for ci,sku in enumerate(skus,5):
                    q=sq.get(sku,0)
                    if q: ws.cell(dr,ci).value=q; cst[sku]+=q; gt[sku]+=q
                ws.cell(dr,5+len(skus)).value=tq; ws.cell(dr,6+len(skus)).value=tc
                cqt+=tq; cct+=tc; gc+=tc; dr+=1
            ws.cell(dr,4).value=f'{cour} TOTAL'; ws.cell(dr,4).font=BOLD
            for ci,sku in enumerate(skus,5):
                if cst[sku]: c=ws.cell(dr,ci,cst[sku]); c.font=BOLD
            ws.cell(dr,5+len(skus)).value=cqt; ws.cell(dr,5+len(skus)).font=BOLD
            ws.cell(dr,6+len(skus)).value=cct; ws.cell(dr,6+len(skus)).font=BOLD; dr+=1
        ws.cell(dr,4).value='Grand Total'; ws.cell(dr,4).font=BOLD; ws.cell(dr,4).fill=GREY
        for ci,sku in enumerate(skus,5):
            if gt[sku]: c=ws.cell(dr,ci,gt[sku]); c.font=BOLD; c.fill=GREY
        s=sum(gt.values()); c1=ws.cell(dr,5+len(skus),s); c1.font=BOLD; c1.fill=GREY
        c2=ws.cell(dr,6+len(skus),gc); c2.font=BOLD; c2.fill=GREY; dr+=1
        ws.cell(dr,1).value='Discrepancies:'; ws.cell(dr+1,1).value='Discrepancies Sent to Sophie?'; ws.cell(dr+1,4).value=False
        return dr+3
    nr=write_section(3,SKUS_350,'350','WHITE','350ml')
    nr=write_section(nr,SKUS_TEA,'TEA','CLEAR','Tea')
    nr=write_section(nr,SKUS_1L,'1L','WHITE','1L')
    p=f'{OUT_DIR}/{DATE_STR}_Production_Sheet.xlsx'; wb.save(p); generated.append(p)

if GEN_TYPE in ('prints','all'):
    AF=r'J:\\My Drive\\Print Files'; AB=r'G:\\My Drive\\Print Files'
    PH=['Order','#file','SKU','#copies','Customer','Customer ID','.PDF','CODE','#pages','#papersize','#duplex','#orientation','#trayname']
    sr=sorted(rows,key=lambda r:(r.get('Courier',''),r.get('Customer',''),r.get('OrderNumber',''),r.get('SKU','')))
    def mk_print(name,data,is_back,addr):
        wb2=Workbook(); ws2=wb2.active; ws2.title='BACKS' if is_back else 'FRONTS'
        for ci,h in enumerate(PH,1): c=ws2.cell(1,ci,h); c.font=BOLD; c.fill=GREY
        cb=24 if '350' in name else 18 if 'Tea' in name else 12; tot=len(data)+2
        if is_back:
            n=tot; ws2.cell(2,1).value=n; ws2.cell(2,2).value=addr+'\\\\BLANK\\\\BLANK.PDF'; ws2.cell(2,3).value='BLANK'; ws2.cell(2,4).value=cb; n-=1
            for di,r in enumerate(data,3):
                bl=r.get('BackLabels','BACKS'); ws2.cell(di,1).value=n; ws2.cell(di,2).value=addr+'\\\\'+bl+'\\\\'+r['SKU']+'.PDF'
                ws2.cell(di,3).value=r['SKU']; ws2.cell(di,4).value=int(r.get('Quantity',0)); ws2.cell(di,5).value=r.get('Customer',''); ws2.cell(di,6).value=bl; ws2.cell(di,7).value='.PDF'; n-=1
            ws2.cell(tot+1,1).value=n; ws2.cell(tot+1,2).value=addr+'\\\\BLANK\\\\BLANK.PDF'; ws2.cell(tot+1,3).value='BLANK'; ws2.cell(tot+1,4).value=cb
        else:
            n=1; ws2.cell(2,1).value=n; ws2.cell(2,2).value=addr+'\\\\BLANK\\\\BLANK.PDF'; ws2.cell(2,3).value='BLANK'; ws2.cell(2,4).value=cb; n+=1
            for di,r in enumerate(data,3):
                ws2.cell(di,1).value=n; ws2.cell(di,2).value=addr+'\\\\'+r['CustomerId']+'\\\\'+r['SKU']+'.PDF'
                ws2.cell(di,3).value=r['SKU']; ws2.cell(di,4).value=int(r.get('Quantity',0)); ws2.cell(di,5).value=r.get('Customer',''); ws2.cell(di,6).value=r.get('CustomerId',''); ws2.cell(di,7).value='.PDF'; n+=1
            ws2.cell(tot+1,1).value=n; ws2.cell(tot+1,2).value=addr+'\\\\BLANK\\\\BLANK.PDF'; ws2.cell(tot+1,3).value='BLANK'; ws2.cell(tot+1,4).value=cb
        p=f'{OUT_DIR}/{DATE_STR}_{name}.xlsx'; wb2.save(p); generated.append(p)
    r3=[r for r in sr if r.get('Product')=='350']; rt=[r for r in sr if r.get('Product')=='TEA']; r1=[r for r in sr if r.get('Product')=='1L']
    mk_print('350ml_Fronts',r3,False,AF); mk_print('350ml_Backs',r3,True,AB)
    mk_print('Tea_Fronts',rt,False,AF); mk_print('Tea_Backs',rt,True,AB)
    mk_print('1L_Fronts',r1,False,AF)

if GEN_TYPE=='all':
    zip_path=f'{OUT_DIR}/{DATE_STR}_Wholesale_State_Files.zip'
    import zipfile as zf2
    with zf2.ZipFile(zip_path,'w',zf2.ZIP_DEFLATED) as z:
        for fp in generated: z.write(fp,os.path.basename(fp))
    print(json.dumps({'zip':zip_path,'files':[os.path.basename(f) for f in generated]}))
else:
    print(json.dumps({'files':[os.path.basename(f) for f in generated],'paths':generated}))
`;

    await _writeFile(pyPath, py);
    const { stdout, stderr } = await execAsync(`python3 ${pyPath}`);
    if (!stdout && stderr) throw new Error(stderr);
    const result = JSON.parse(stdout.trim());

    if (type === 'all' && result.zip) {
      const zipData = await _readFile(result.zip);
      res.setHeader('Content-Type','application/zip');
      res.setHeader('Content-Disposition',`attachment; filename="${d}_Wholesale_State_Files.zip"`);
      return res.send(zipData);
    }
    if (result.paths && result.paths.length > 0) {
      const fileData = await _readFile(result.paths[0]);
      res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition',`attachment; filename="${result.files[0]}"`);
      return res.send(fileData);
    }
    res.status(500).json({ error: 'No files generated' });
  } catch(e) {
    console.error('Generate error:', e.message);
    res.status(500).json({ error: e.message });
  }
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
