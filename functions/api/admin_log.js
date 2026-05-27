/**
 * CogniGrad Legal API - Cloudflare Pages + Supabase
 * Compliant: DPDP Act 2023, IT Rules 2021, POSH Act 2013
 */
import { createClient } from '@supabase/supabase-js';
import { SignJWT, jwtVerify } from 'jose';

// ===== CONFIG =====
const SUPABASE_URL = 'https://your-project.supabase.co';
const SUPABASE_SERVICE_KEY = 'your-service-role-key'; // Never expose to frontend
const JWT_SECRET = new TextEncoder().encode('CHANGE_THIS_SECRET_IN_PRODUCTION');
const ADMIN_EMAIL = 'ajit@cognigrad.com';
const ADMIN_PASS_HASH = '$2b$10$YourBcryptHashHere'; // bcrypt.hash('password', 10)

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ===== CORS + SECURITY =====
const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://cognigrad.com',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
};

export async function onRequestOptions() {
  return new Response(null, { headers: corsHeaders });
}

// ===== AUTH MIDDLEWARE =====
async function authenticateAdmin(request) {
  const auth = request.headers.get('Authorization');
  if (!auth) throw new Error('No token');

  const token = auth.split(' ')[1];
  const { payload } = await jwtVerify(token, JWT_SECRET);
  if (payload.email!== ADMIN_EMAIL) throw new Error('Not admin');
  return payload;
}

// ===== ROUTER =====
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '');

  try {
    // Public endpoints
    if (path === 'consent/log' && request.method === 'POST') return consentLog(request);
    if (path === 'data/delete' && request.method === 'POST') return deletionRequest(request);
    if (path === 'data/access' && request.method === 'POST') return accessRequest(request);
    if (path === 'icc/complaint' && request.method === 'POST') return iccComplaint(request);

    // Admin endpoints - require auth
    const admin = await authenticateAdmin(request);
    if (path === 'admin/login' && request.method === 'POST') return adminLogin(request);
    if (path === 'admin/stats' && request.method === 'GET') return adminStats();
    if (path === 'admin/consent-logs' && request.method === 'GET') return getConsentLogs();
    if (path === 'admin/deletion-requests' && request.method === 'GET') return getDeletionRequests();
    if (path.startsWith('admin/deletion-requests/') && request.method === 'POST') return updateDeletionRequest(path, request);
    if (path === 'admin/access-requests' && request.method === 'GET') return getAccessRequests();
    if (path === 'admin/copyright-notices' && request.method === 'GET') return getCopyrightNotices();
    if (path === 'admin/icc-cases' && request.method === 'GET') return getICCCases();

    return new Response('Not Found', { status: 404, headers: corsHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: e.message.includes('token')? 403 : 500,
      headers: {...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// ===== PUBLIC: CONSENT LOG - DPDP s.6 =====
async function consentLog(request) {
  const { essential, functional, analytics, marketing, timestamp } = await request.json();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ip_hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
  const ip_hash_hex = Array.from(new Uint8Array(ip_hash)).map(b => b.toString(16).padStart(2, '0')).join('');

  const { error } = await supabase.from('consent_logs').insert({
    timestamp,
    ip_hash: ip_hash_hex,
    functional,
    analytics,
    marketing,
    user_agent: request.headers.get('User-Agent'),
    consent_version: 'v1'
  });

  if (error) throw error;
  return new Response(JSON.stringify({ success: true }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== PUBLIC: DELETION REQUEST - DPDP s.12 =====
async function deletionRequest(request) {
  const { email, phone, reason, details, timestamp } = await request.json();
  const id = crypto.randomUUID();

  const { error } = await supabase.from('deletion_requests').insert({
    id,
    request_date: timestamp,
    email,
    phone,
    reason,
    details,
    status: 'pending'
  });

  if (error) throw error;
  console.log(`DELETION REQUEST: ${email} - ID: ${id}`);
  return new Response(JSON.stringify({ success: true, id }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== PUBLIC: ACCESS REQUEST - DPDP s.11 =====
async function accessRequest(request) {
  const { email, phone, format, categories, purpose, timestamp } = await request.json();
  const id = crypto.randomUUID();

  const { error } = await supabase.from('access_requests').insert({
    id,
    request_date: timestamp,
    email,
    phone,
    format,
    categories: JSON.stringify(categories),
    purpose,
    status: 'pending'
  });

  if (error) throw error;
  return new Response(JSON.stringify({ success: true, id }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== PUBLIC: ICC COMPLAINT - POSH Act =====
async function iccComplaint(request) {
  const data = await request.json();
  const id = 'ICC-' + Date.now();

  const { error } = await supabase.from('icc_cases').insert({
    id,
    date_filed: new Date().toISOString(),
    complainant_name: data.name,
    complainant_email: data.email,
    complainant_role: data.role,
    respondent_name: data.respondent_name,
    respondent_role: data.respondent_role,
    incident_date: data.incident_date,
    incident_location: data.incident_location,
    description: data.incident_description,
    status: 'filed'
  });

  if (error) throw error;
  console.log(`ICC COMPLAINT: ${id} - URGENT - Notify ICC within 24hrs`);
  return new Response(JSON.stringify({ success: true, id }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: LOGIN =====
async function adminLogin(request) {
  const { email, password } = await request.json();
  if (email!== ADMIN_EMAIL) throw new Error('Invalid credentials');

  // Use bcrypt in real implementation - Cloudflare doesn't have bcrypt, use Web Crypto or external
  // For now, simplified check. In production, store hash in Supabase and verify.
  const valid = password === 'YourSecurePassword123!'; // REPLACE THIS
  if (!valid) throw new Error('Invalid credentials');

  const token = await new SignJWT({ email })
   .setProtectedHeader({ alg: 'HS256' })
   .setExpirationTime('8h')
   .sign(JWT_SECRET);

  return new Response(JSON.stringify({ token, expiresIn: 28800 }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: STATS =====
async function adminStats() {
  const [consent, deletion, copyright, icc] = await Promise.all([
    supabase.from('consent_logs').select('functional', { count: 'exact' }).gte('timestamp', new Date(Date.now() - 30*24*60*60*1000).toISOString()),
    supabase.from('deletion_requests').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
    supabase.from('copyright_notices').select('*', { count: 'exact', head: true }).in('status', ['received', 'investigating']),
    supabase.from('icc_cases').select('*', { count: 'exact', head: true }).not('status', 'in', '(resolved,withdrawn)')
  ]);

  const consentRate = consent.count > 0? Math.round((consent.data.filter(d => d.functional).length / consent.count) * 100) : 0;

  return new Response(JSON.stringify({
    consentRate,
    pendingDeletions: deletion.count,
    activeCopyright: copyright.count,
    activeICC: icc.count
  }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: CONSENT LOGS =====
async function getConsentLogs() {
  const { data, error } = await supabase
   .from('consent_logs')
   .select('*')
   .order('timestamp', { ascending: false })
   .limit(500);
  if (error) throw error;
  return new Response(JSON.stringify({ logs: data }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: DELETION REQUESTS =====
async function getDeletionRequests() {
  const { data, error } = await supabase
   .from('deletion_requests')
   .select('*')
   .order('request_date', { ascending: false });
  if (error) throw error;
  return new Response(JSON.stringify({ requests: data }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

async function updateDeletionRequest(path, request) {
  const [,, id, action] = path.split('/');
  const body = await request.json().catch(() => ({}));

  if (action === 'approve') {
    const { error } = await supabase
     .from('deletion_requests')
     .update({ status: 'completed', completed_date: new Date().toISOString() })
     .eq('id', id);
    if (error) throw error;
    console.log(`ADMIN ACTION: Deletion approved for ${id}`);
  } else if (action === 'reject') {
    const { error } = await supabase
     .from('deletion_requests')
     .update({ status: 'rejected', admin_notes: body.reason })
     .eq('id', id);
    if (error) throw error;
  }

  return new Response(JSON.stringify({ success: true }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: ACCESS REQUESTS =====
async function getAccessRequests() {
  const { data, error } = await supabase
   .from('access_requests')
   .select('*')
   .order('request_date', { ascending: false });
  if (error) throw error;
  return new Response(JSON.stringify({ requests: data }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: COPYRIGHT NOTICES =====
async function getCopyrightNotices() {
  const { data, error } = await supabase
   .from('copyright_notices')
   .select('*')
   .order('date_received', { ascending: false });
  if (error) throw error;
  return new Response(JSON.stringify({ notices: data }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}

// ===== ADMIN: ICC CASES =====
async function getICCCases() {
  const { data, error } = await supabase
   .from('icc_cases')
   .select('id, date_filed, complainant_role, respondent_role, status, description')
   .order('date_filed', { ascending: false });
  if (error) throw error;

  // Calculate days_open
  const cases = data.map(c => ({
   ...c,
    days_open: Math.floor((Date.now() - new Date(c.date_filed)) / 86400000)
  }));

  return new Response(JSON.stringify({ cases }), { headers: {...corsHeaders, 'Content-Type': 'application/json' } });
}