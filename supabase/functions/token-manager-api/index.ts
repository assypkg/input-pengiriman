// Superuser-only API for managing Firestore access_tokens.
// Firebase service-account credentials and OAuth access tokens stay server-side.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

function base64url(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function pemToDer(pem: string): ArrayBuffer {
  const clean = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function signJwt(serviceAccount: any, claims: Record<string, unknown>) {
  const now = Math.floor(Date.now() / 1000);
  const unsigned = [
    base64url(JSON.stringify({ alg: "RS256", typ: "JWT" })),
    base64url(JSON.stringify({
      iss: serviceAccount.client_email,
      sub: serviceAccount.client_email,
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
      ...claims,
    })),
  ].join(".");
  const key = await crypto.subtle.importKey(
    "pkcs8", pemToDer(serviceAccount.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned),
  ));
  return unsigned + "." + base64url(signature);
}
async function getGoogleAccessToken(serviceAccount: any): Promise<string> {
  const assertion = await signJwt(serviceAccount, {
    scope: "https://www.googleapis.com/auth/datastore",
  });
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const payload = await response.json();
  if (!response.ok || !payload.access_token) {
    console.error("Google OAuth token error", payload.error || response.status);
    throw new Error("Tidak dapat membuat sesi Firestore.");
  }
  return payload.access_token;
}
function toFirestoreValue(value: any): any {
  if (value === null) return { nullValue: null };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }
  if (Array.isArray(value)) return { arrayValue: { values: value.map(toFirestoreValue) } };
  if (typeof value === "object") {
    const fields: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) fields[key] = toFirestoreValue(item);
    return { mapValue: { fields } };
  }
  throw new Error("Tipe data Firestore tidak didukung.");
}
function fromFirestoreValue(value: any): any {
  if (!value || typeof value !== "object") return null;
  if ("nullValue" in value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return value.doubleValue;
  if ("timestampValue" in value) return value.timestampValue;
  if ("arrayValue" in value) return (value.arrayValue.values || []).map(fromFirestoreValue);
  if ("mapValue" in value) return fromFirestoreFields(value.mapValue.fields || {});
  return null;
}
function fromFirestoreFields(fields: Record<string, any>) {
  const result: Record<string, any> = {};
  for (const [key, value] of Object.entries(fields)) result[key] = fromFirestoreValue(value);
  return result;
}
function validSchedule(schedule: any): boolean {
  if (!schedule || typeof schedule !== "object" || typeof schedule.isScheduled !== "boolean") return false;
  if (!schedule.isScheduled) return true;
  const validPart = (part: any) =>
    part && typeof part.time === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(part.time) &&
    ["tiap_hari", "senin_jumat", "sekali", "khusus"].includes(part.type) &&
    Array.isArray(part.days) && part.days.every((day: any) => Number.isInteger(day) && day >= 0 && day <= 6);
  return validPart(schedule.start) && validPart(schedule.end) &&
    typeof schedule.createdAt === "string";
}
function safeDocId(id: any): id is string {
  return typeof id === "string" && /^[A-Za-z0-9_-]{1,150}$/.test(id);
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const projectId = Deno.env.get("FIREBASE_PROJECT_ID") || "summarypengiriman";
    const serviceAccountRaw = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON");
    const bearer = req.headers.get("Authorization") || "";
    const accessToken = bearer.startsWith("Bearer ") ? bearer.slice(7) : "";
    if (!supabaseUrl || !anonKey || !serviceKey || !serviceAccountRaw) {
      return json({ error: "Konfigurasi server belum lengkap." }, 500);
    }
    if (!accessToken) return json({ error: "Login superuser diperlukan." }, 401);

    const caller = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: authData, error: authError } = await caller.auth.getUser();
    if (authError || !authData.user) return json({ error: "Sesi login tidak valid." }, 401);

    const admin = createClient(supabaseUrl, serviceKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: profile, error: profileError } = await admin
      .from("assembly_users")
      .select("username,role,is_active")
      .eq("user_id", authData.user.id)
      .maybeSingle();
    if (profileError) return json({ error: "Gagal memeriksa hak akses." }, 503);
    if (!profile || profile.is_active !== true || profile.role !== "superuser") {
      return json({ error: "Hanya superuser aktif yang dapat mengelola token." }, 403);
    }

    const serviceAccount = JSON.parse(serviceAccountRaw);
    if (serviceAccount.project_id !== projectId || !serviceAccount.client_email || !serviceAccount.private_key) {
      return json({ error: "Konfigurasi Firebase service account tidak sesuai." }, 500);
    }
    const googleToken = await getGoogleAccessToken(serviceAccount);
    const base = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;
    const headers = { Authorization: `Bearer ${googleToken}`, "Content-Type": "application/json" };
    const readCollection = async () => {
      const all: any[] = [];
      let pageToken = "";
      do {
        const query = new URLSearchParams({ pageSize: "1000" });
        if (pageToken) query.set("pageToken", pageToken);
        const response = await fetch(`${base}/access_tokens?${query}`, { headers });
        const payload = await response.json();
        if (!response.ok) throw new Error("Gagal membaca daftar token dari Firestore.");
        for (const document of payload.documents || []) {
          all.push({ id: document.name.split("/").pop(), ...fromFirestoreFields(document.fields || {}) });
        }
        pageToken = payload.nextPageToken || "";
      } while (pageToken);
      return all;
    };

    const body = await req.json();
    const action = body?.action;
    if (!["list", "create", "update", "toggle", "reset", "delete"].includes(action)) {
      return json({ error: "Aksi tidak dikenal." }, 400);
    }

    if (action === "list") return json({ success: true, tokens: await readCollection() });

    const docId = body?.docId;
    if (action !== "create" && !safeDocId(docId)) return json({ error: "ID token tidak valid." }, 400);

    if (action === "create") {
      const nama = typeof body.nama === "string" ? body.nama.trim() : "";
      const token = typeof body.token === "string" ? body.token.trim().toUpperCase() : "";
      const maxDevices = body.maxDevices;
      const schedule = body.schedule;
      if (!nama || nama.length > 120 || !/^[A-Z0-9_-]{3,80}$/.test(token) ||
          !Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100 ||
          !validSchedule(schedule)) {
        return json({ error: "Data token tidak valid." }, 400);
      }
      const existing = await readCollection();
      if (existing.some((item) => String(item.token || "").toUpperCase() === token)) {
        return json({ error: "Kode token sudah digunakan." }, 409);
      }
      const newId = crypto.randomUUID().replace(/-/g, "");
      const fields = {
        nama: toFirestoreValue(nama),
        token: toFirestoreValue(token),
        active: toFirestoreValue(true),
        maxDevices: toFirestoreValue(maxDevices),
        registeredDevices: toFirestoreValue([]),
        schedule: toFirestoreValue(schedule),
      };
      const response = await fetch(`${base}/access_tokens?documentId=${encodeURIComponent(newId)}`, {
        method: "POST", headers, body: JSON.stringify({ fields }),
      });
      const payload = await response.json();
      if (!response.ok) {
        console.error("Firestore create error", payload.error?.status || response.status);
        return json({ error: "Gagal membuat token di Firestore." }, 502);
      }
      return json({ success: true, token: { id: newId, nama, token, active: true, maxDevices, registeredDevices: [], schedule } }, 201);
    }

    const documentUrl = `${base}/access_tokens/${encodeURIComponent(docId)}`;
    const currentResponse = await fetch(documentUrl, { headers });
    if (currentResponse.status === 404) return json({ error: "Token tidak ditemukan." }, 404);
    const currentPayload = await currentResponse.json();
    if (!currentResponse.ok) return json({ error: "Gagal membaca data token." }, 502);
    const current = fromFirestoreFields(currentPayload.fields || {});

    if (action === "delete") {
      const response = await fetch(documentUrl, { method: "DELETE", headers });
      if (!response.ok) return json({ error: "Gagal menghapus token." }, 502);
      return json({ success: true });
    }

    let updates: Record<string, any>;
    if (action === "update") {
      const maxDevices = body.maxDevices;
      const schedule = body.schedule;
      if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100 || !validSchedule(schedule)) {
        return json({ error: "Pengaturan token tidak valid." }, 400);
      }
      updates = { maxDevices, schedule };
    } else if (action === "toggle") {
      updates = { active: current.active !== true };
    } else {
      updates = { registeredDevices: [] };
    }

    const fields: Record<string, any> = {};
    for (const [key, value] of Object.entries(updates)) fields[key] = toFirestoreValue(value);
    const query = new URLSearchParams();
    for (const key of Object.keys(updates)) query.append("updateMask.fieldPaths", key);
    const response = await fetch(`${documentUrl}?${query}`, {
      method: "PATCH", headers, body: JSON.stringify({ fields }),
    });
    const payload = await response.json();
    if (!response.ok) {
      console.error("Firestore update error", payload.error?.status || response.status);
      return json({ error: "Gagal memperbarui token." }, 502);
    }
    return json({ success: true, updates });
  } catch (error) {
    console.error("token-manager-api", error);
    return json({ error: error instanceof Error ? error.message : "Permintaan tidak dapat diproses." }, 500);
  }
});
