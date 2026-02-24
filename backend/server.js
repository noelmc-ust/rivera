import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { nanoid } from 'nanoid';

dotenv.config();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const NODE_ENV = process.env.NODE_ENV || 'development';

const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || 'larivera';
const DB_CONN_LIMIT = Number(process.env.DB_CONN_LIMIT || 10);

const app = express();
app.use(express.json());
if (NODE_ENV !== 'production') app.use(cors());

const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: DB_CONN_LIMIT,
  queueLimit: 0
});

async function initSchema(seed = false){
  const conn = await pool.getConnection();
  try{
    await conn.query(`CREATE TABLE IF NOT EXISTS users (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS products (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      price_cents INT NOT NULL,
      image_url TEXT
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS carts (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id BIGINT NOT NULL,
      UNIQUE KEY uniq_user_cart (user_id),
      CONSTRAINT fk_carts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS cart_items (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      cart_id BIGINT NOT NULL,
      product_id BIGINT NOT NULL,
      qty INT NOT NULL,
      UNIQUE KEY uniq_cart_product (cart_id, product_id),
      CONSTRAINT fk_cartitems_cart FOREIGN KEY (cart_id) REFERENCES carts(id) ON DELETE CASCADE,
      CONSTRAINT fk_cartitems_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS orders (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id BIGINT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      total_cents INT NOT NULL,
      CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS order_items (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      order_id BIGINT NOT NULL,
      product_id BIGINT NOT NULL,
      name VARCHAR(255) NOT NULL,
      qty INT NOT NULL,
      price_cents INT NOT NULL,
      subtotal_cents INT NOT NULL,
      CONSTRAINT fk_orderitems_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
      CONSTRAINT fk_orderitems_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
    ) ENGINE=InnoDB`);

    if (seed) {
      const [rows] = await conn.query('SELECT COUNT(*) AS c FROM products');
      if (rows[0].c === 0) {
        await conn.query(`INSERT INTO products (name, description, price_cents, image_url) VALUES
          ('Aurelia Silk Gown','Floor-length silk evening gown with a timeless silhouette.',12999,'https://images.unsplash.com/photo-1519741497674-611481863552?q=80&w=1200&auto=format&fit=crop'),
          ('Nocturne Velvet Dress','Midnight velvet with subtle shimmer, long sleeves.',9999,'https://images.unsplash.com/photo-1520975682031-ae1e76607f66?q=80&w=1200&auto=format&fit=crop'),
          ('Éclat Cocktail Dress','Knee-length satin dress with minimalist lines.',7999,'https://images.unsplash.com/photo-1503341455253-b2e723bb3dbb?q=80&w=1200&auto=format&fit=crop'),
          ('Seraphina Lace Midi','Delicate lace midi dress in pearl white.',10999,'https://images.unsplash.com/photo-1506863530036-1efeddceb993?q=80&w=1200&auto=format&fit=crop'),
          ('Valencia Slip Dress','Silky slip dress with adjustable straps.',6999,'https://images.unsplash.com/photo-1541099649105-f69ad21f3246?q=80&w=1200&auto=format&fit=crop')`);
      }
    }
  } finally {
    conn.release();
  }
}

function sign(user) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.name, created_at: user.created_at }, JWT_SECRET, { expiresIn: '4h' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/health', (_req, res) => res.status(200).send('OK'));

// Auth: Signup
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const conn = await pool.getConnection();
  try {
    const [exists] = await conn.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Email already registered' });
    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await conn.query('INSERT INTO users (name, email, password_hash) VALUES (?,?,?)', [name, email, password_hash]);
    const userId = result.insertId;
    await conn.query('INSERT INTO carts (user_id) VALUES (?)', [userId]);
    const [[user]] = await conn.query('SELECT id, name, email, created_at FROM users WHERE id = ?', [userId]);
    const token = sign(user);
    res.json({ token, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const conn = await pool.getConnection();
  try {
    const [[user]] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = sign(user);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, created_at: user.created_at } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// Current user
app.get('/api/me', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [[user]] = await conn.query('SELECT id, name, email, created_at FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ user });
  } finally { conn.release(); }
});

// Products
app.get('/api/products', async (_req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query('SELECT id, name, description, price_cents, image_url FROM products ORDER BY id');
    res.json({ products: rows });
  } finally { conn.release(); }
});

// Cart
app.get('/api/cart', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [[cart]] = await conn.query('SELECT id FROM carts WHERE user_id = ?', [req.user.sub]);
    if (!cart) return res.json({ items: [] });
    const [items] = await conn.query(`
      SELECT ci.product_id, ci.qty
      FROM cart_items ci WHERE ci.cart_id = ?
    `, [cart.id]);
    res.json({ items });
  } finally { conn.release(); }
});

app.post('/api/cart/add', authMiddleware, async (req, res) => {
  const { productId, qty } = req.body || {};
  if (!productId || !qty || qty < 1) return res.status(400).json({ error: 'Invalid payload' });
  const conn = await pool.getConnection();
  try {
    const [[cart]] = await conn.query('SELECT id FROM carts WHERE user_id = ?', [req.user.sub]);
    if (!cart) return res.status(400).json({ error: 'Cart missing' });
    const [[existing]] = await conn.query('SELECT id, qty FROM cart_items WHERE cart_id = ? AND product_id = ?', [cart.id, productId]);
    if (existing) {
      await conn.query('UPDATE cart_items SET qty = ? WHERE id = ?', [existing.qty + qty, existing.id]);
    } else {
      await conn.query('INSERT INTO cart_items (cart_id, product_id, qty) VALUES (?,?,?)', [cart.id, productId, qty]);
    }
    res.json({ ok: true });
  } finally { conn.release(); }
});

app.post('/api/cart/remove', authMiddleware, async (req, res) => {
  const { productId } = req.body || {};
  const conn = await pool.getConnection();
  try {
    const [[cart]] = await conn.query('SELECT id FROM carts WHERE user_id = ?', [req.user.sub]);
    if (!cart) return res.json({ ok: true });
    await conn.query('DELETE FROM cart_items WHERE cart_id = ? AND product_id = ?', [cart.id, productId]);
    res.json({ ok: true });
  } finally { conn.release(); }
});

// Orders
app.get('/api/orders', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [orders] = await conn.query('SELECT id, user_id, created_at, total_cents FROM orders WHERE user_id = ? ORDER BY created_at DESC', [req.user.sub]);
    const orderIds = orders.map(o => o.id);
    let itemsByOrder = {};
    if (orderIds.length) {
      const [items] = await conn.query('SELECT order_id, name, qty, price_cents, subtotal_cents FROM order_items WHERE order_id IN (?)', [orderIds]);
      for (const it of items) {
        (itemsByOrder[it.order_id] ||= []).push(it);
      }
    }
    const combined = orders.map(o => ({ ...o, line_items: itemsByOrder[o.id] || [] }));
    res.json({ orders: combined });
  } finally { conn.release(); }
});

app.post('/api/orders/checkout', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[cart]] = await conn.query('SELECT id FROM carts WHERE user_id = ? FOR UPDATE', [req.user.sub]);
    if (!cart) { await conn.rollback(); return res.status(400).json({ error: 'Cart missing' }); }

    const [items] = await conn.query('SELECT product_id, qty FROM cart_items WHERE cart_id = ?', [cart.id]);
    if (!items.length) { await conn.rollback(); return res.status(400).json({ error: 'Cart empty' }); }

    // Load products
    const productIds = items.map(i => i.product_id);
    const [products] = await conn.query('SELECT id, name, price_cents FROM products WHERE id IN (?)', [productIds]);
    const pmap = new Map(products.map(p => [p.id, p]));

    let total = 0;
    const lines = items.map(i => {
      const p = pmap.get(i.product_id);
      const subtotal = p.price_cents * i.qty;
      total += subtotal;
      return { product_id: p.id, name: p.name, qty: i.qty, price_cents: p.price_cents, subtotal_cents: subtotal };
    });

    const [orderRes] = await conn.query('INSERT INTO orders (user_id, total_cents) VALUES (?, ?)', [req.user.sub, total]);
    const orderId = orderRes.insertId;

    const values = lines.map(l => [orderId, l.product_id, l.name, l.qty, l.price_cents, l.subtotal_cents]);
    await conn.query('INSERT INTO order_items (order_id, product_id, name, qty, price_cents, subtotal_cents) VALUES ?',[values]);

    // Clear cart
    await conn.query('DELETE FROM cart_items WHERE cart_id = ?', [cart.id]);

    await conn.commit();
    res.json({ order: { id: orderId, user_id: req.user.sub, total_cents: total, line_items: lines, created_at: new Date().toISOString() } });
  } catch (e) {
    console.error('Checkout error', e);
    try { await conn.rollback(); } catch {}
    res.status(500).json({ error: 'Checkout failed' });
  } finally {
    conn.release();
  }
});

(async function start(){
  const doInit = process.argv.includes('--initdb');
  const doSeed = process.argv.includes('--seed');
  if (doInit) {
    await initSchema(doSeed);
    if (!process.argv.includes('--keep-running')) {
      console.log('DB init done');
      process.exit(0);
    }
  } else {
    await initSchema(false);
  }
  app.listen(PORT, () => console.log(`La Rivera (MySQL) API listening on :${PORT}`));
})();
