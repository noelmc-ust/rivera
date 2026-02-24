// frontend/js/api.js

// For local dev across ports (e.g., Live Server :5500), set:
//   const API_BASE = 'http://localhost:4000';
// For AWS behind ALB (same-origin), set:
const API_BASE = '';

function authHeader() {
  const t = localStorage.getItem('token');
  return t ? { 'Authorization': 'Bearer ' + t } : {};
}

export async function apiGet(path, auth = false) {
  const res = await fetch(API_BASE + path, {
    headers: auth ? authHeader() : {}
  });
  const data = await res.json().catch(() => ({ error: 'Invalid JSON' }));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

export async function apiPost(path, body, auth = false) {
  const res = await fetch(API_BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(auth ? authHeader() : {}) },
    body: JSON.stringify(body || {})
  });
  const data = await res.json().catch(() => ({ error: 'Invalid JSON' }));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}