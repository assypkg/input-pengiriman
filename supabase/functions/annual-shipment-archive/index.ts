// Annual shipment archive lifecycle for Assembly.
// Grouping is always based on delivery date (record.tanggal), never JO prefix.
// Cloud purge requires a FINAL year and a separately verified local JSON backup.

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

const BUCKET = "arsip-pengiriman";
const RECORD_PREFIX = "records/";
const MANIFEST_PREFIX = "annual-manifests/";
const MAX_FIRESTORE_DOCS = 20000;
const PURGE_BATCH_SIZE = 400;
type Context = { url: string; serviceKey: string };

function jakartaToday(): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Jakarta", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(new Date());
  const get = (name: string) => parts.find((p) => p.type === name)?.value || "";
  return get("year") + "-" + get("month") + "-" + get("day");
}
function validYear(value: unknown): string {
  const year = String(value ?? "");
  return /^\d{4}$/.test(year) && Number(year) >= 2000 && Number(year) <= 2100 ? year : "";
}
function addDays(dateString: string, days: number): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateString)) return "";
  const [year, month, day] = dateString.split("-").map(Number);
  const original = new Date(Date.UTC(year, month - 1, day));
  if (original.getUTCFullYear() !== year || original.getUTCMonth() !== month - 1 || original.getUTCDate() !== day) return "";
  const date = new Date(Date.UTC(year, month - 1, day + days));
  return date.getUTCFullYear() + "-" + String(date.getUTCMonth() + 1).padStart(2, "0") + "-" +
    String(date.getUTCDate()).padStart(2, "0");
}
function hPlusOnePassed(date: string): boolean {
  const hPlusOne = addDays(date, 1);
  return !!hPlusOne && jakartaToday() > hPlusOne;
}
function remainingQty(record: Record<string, any>): number {
  if (record.sisa !== undefined && record.sisa !== null && String(record.sisa).trim() !== "") {
    const value = Number(record.sisa);
    return Number.isFinite(value) ? value : Number.NaN;
  }
  const order = Number(record.order), hasil = Number(record.hasil);
  return Number.isFinite(order) && Number.isFinite(hasil) ? order - hasil : Number.NaN;
}
function isClosed(record: Record<string, any>): boolean {
  const remaining = remainingQty(record);
  return Number.isFinite(remaining) && remaining <= 0;
}
function canonicalize(value: any): any {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const output: Record<string, any> = {};
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}
function canonicalJson(value: any): string {
  return JSON.stringify(canonicalize(value));
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function base64UrlEncode(value: string | Uint8Array): string {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function firestoreValueToJs(value: any): any {
  if (!value || typeof value !== "object") return null;
  if ("nullValue" in value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("timestampValue" in value) return value.timestampValue;
  if ("referenceValue" in value) return value.referenceValue;
  if ("bytesValue" in value) return value.bytesValue;
  if ("arrayValue" in value) return (value.arrayValue?.values || []).map(firestoreValueToJs);
  if ("mapValue" in value) return firestoreFieldsToJs(value.mapValue?.fields || {});
  return null;
}
function firestoreFieldsToJs(fields: Record<string, any>): Record<string, any> {
  const output: Record<string, any> = {};
  for (const [key, value] of Object.entries(fields || {})) output[key] = firestoreValueToJs(value);
  return output;
}
async function getFirebaseAccessToken(): Promise<{ projectId: string; accessToken: string }> {
  const raw = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON");
  if (!raw) throw new Error("Secret FIREBASE_SERVICE_ACCOUNT_JSON belum dipasang pada Supabase Edge Functions.");
  let account: any;
  try { account = JSON.parse(raw); } catch (_) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON bukan JSON service account yang valid.");
  }
  if (!account.project_id || !account.client_email || !account.private_key) {
    throw new Error("Service account Firebase harus memiliki project_id, client_email, dan private_key.");
  }
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64UrlEncode(JSON.stringify({
    iss: account.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  }));
  const unsignedJwt = header + "." + claims;
  const pem = String(account.private_key).replace(/\\n/g, "\n");
  const keyBody = pem.replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "").replace(/\s/g, "");
  const privateKey = await crypto.subtle.importKey(
    "pkcs8", Uint8Array.from(atob(keyBody), (c) => c.charCodeAt(0)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(unsignedJwt),
  );
  const assertion = unsignedJwt + "." + base64UrlEncode(new Uint8Array(signature));
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion,
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.access_token) {
    throw new Error("Gagal memperoleh akses Firestore dari Google: " +
      String(payload.error_description || payload.error || "OAuth gagal.").slice(0, 180));
  }
  return { projectId: String(account.project_id), accessToken: String(payload.access_token) };
}
async function listFirestoreRows(firebase: { projectId: string; accessToken: string }) {
  const rows: Array<{ id: string; name: string; record: Record<string, any> }> = [];
  let pageToken = "";
  const baseUrl = "https://firestore.googleapis.com/v1/projects/" +
    encodeURIComponent(firebase.projectId) + "/databases/(default)/documents/production_data_v2";
  do {
    const url = new URL(baseUrl);
    url.searchParams.set("pageSize", "1000");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await fetch(url, { headers: { Authorization: "Bearer " + firebase.accessToken } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error("Gagal membaca production_data_v2 dari Firestore: HTTP " +
      response.status + " " + String(payload.error?.message || "").slice(0, 180));
    for (const document of payload.documents || []) {
      const name = String(document.name || "");
      const id = name.split("/").pop() || "";
      if (id) rows.push({ id, name, record: { ...firestoreFieldsToJs(document.fields || {}), docId: id } });
    }
    pageToken = String(payload.nextPageToken || "");
    if (rows.length > MAX_FIRESTORE_DOCS) {
      throw new Error("Dokumen Firestore melebihi batas aman 20.000 untuk satu proses tahunan.");
    }
  } while (pageToken);
  return rows;
}
async function authorizeAdmin(req: Request): Promise<{ context: Context; profile: any } | Response> {
  const url = Deno.env.get("SUPABASE_URL") || "";
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  const bearer = req.headers.get("Authorization") || "";
  const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : "";
  if (!url || !anonKey || !serviceKey) return json({ success: false, error: "Konfigurasi Supabase server belum lengkap." }, 500);
  if (!token) return json({ success: false, error: "Sesi Admin diperlukan." }, 401);
  const authResponse = await fetch(url + "/auth/v1/user", {
    headers: { apikey: anonKey, Authorization: "Bearer " + token },
  });
  if (!authResponse.ok) return json({ success: false, error: "Sesi Admin tidak valid atau berakhir." }, 401);
  const user = await authResponse.json();
  if (!user?.id) return json({ success: false, error: "Pengguna tidak dapat diverifikasi." }, 401);
  const profileUrl = new URL(url + "/rest/v1/assembly_users");
  profileUrl.searchParams.set("user_id", "eq." + user.id);
  profileUrl.searchParams.set("select", "username,full_name,role,is_active");
  const profileResponse = await fetch(profileUrl, {
    headers: { apikey: serviceKey, Authorization: "Bearer " + serviceKey },
  });
  if (!profileResponse.ok) return json({ success: false, error: "Profil Assembly gagal diverifikasi." }, 503);
  const profiles = await profileResponse.json();
  const profile = profiles?.[0];
  if (!profile || profile.is_active !== true || !["admin", "superuser"].includes(profile.role)) {
    return json({ success: false, error: "Akses ditolak. Hanya Admin atau Superuser yang dapat mengelola backup tahunan." }, 403);
  }
  return { context: { url, serviceKey }, profile };
}
async function authorizeViewer(context: Context, input: any): Promise<Response | null> {
  const token = typeof input?.token === "string" ? input.token.trim().toUpperCase() : "";
  const deviceId = typeof input?.deviceId === "string" ? input.deviceId : "";
  if (!token || token.length > 120 || !/^[A-Za-z0-9_-]{3,80}$/.test(deviceId)) {
    return json({ success: false, error: "Token atau identitas perangkat Viewer tidak valid." }, 400);
  }
  const response = await fetch(context.url + "/functions/v1/validate-viewer-token", {
    method: "POST",
    headers: {
      apikey: context.serviceKey,
      Authorization: "Bearer " + context.serviceKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token, deviceId }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success !== true) {
    return json({ success: false, error: payload.message || "Akses Viewer ditolak." }, response.status >= 400 ? response.status : 403);
  }
  return null;
}
function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}
async function storageRequest(context: Context, path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("apikey", context.serviceKey);
  headers.set("Authorization", "Bearer " + context.serviceKey);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return await fetch(context.url + "/storage/v1" + path, { ...init, headers });
}
async function getStoredJson(context: Context, path: string): Promise<any | null> {
  const response = await storageRequest(context, "/object/" + BUCKET + "/" + encodePath(path));
  if (response.status === 404) return null;
  if (response.status === 400) {
    const details = await response.text();
    if (/object\s+not\s+found|not\s+found/i.test(details)) return null;
    throw new Error("Gagal membaca file Storage: " + details.slice(0, 180));
  }
  if (!response.ok) throw new Error("Gagal membaca file Storage (HTTP " + response.status + ").");
  return await response.json();
}
async function putStoredJson(context: Context, path: string, value: unknown): Promise<void> {
  const response = await storageRequest(context, "/object/" + BUCKET + "/" + encodePath(path), {
    method: "POST", headers: { "x-upsert": "true" }, body: JSON.stringify(value),
  });
  if (!response.ok) throw new Error("Gagal menyimpan manifest tahunan ke Supabase Storage (HTTP " + response.status + ").");
}

async function listAnnualManifests(context: Context) {
  const files: any[] = [];
  for (let offset = 0; offset < 5000; offset += 1000) {
    const response = await storageRequest(context, "/object/list/" + BUCKET, {
      method: "POST",
      body: JSON.stringify({ prefix: MANIFEST_PREFIX, limit: 1000, offset }),
    });
    if (!response.ok) throw new Error("Gagal membaca daftar manifest tahunan.");
    const batch = await response.json();
    if (!Array.isArray(batch)) throw new Error("Daftar manifest tahunan tidak valid.");
    files.push(...batch.filter((f: any) => f && typeof f.name === "string" && f.name.endsWith(".json")));
    if (batch.length < 1000) return files;
  }
  throw new Error("Jumlah manifest tahunan melebihi batas aman.");
}

async function mergeDeletedAnnualSummaries(context: Context, years: any[]) {
  const files = await listAnnualManifests(context);
  const known = new Set(years.map((item) => String(item.year)));
  for (const file of files) {
    const path = String(file.name).startsWith(MANIFEST_PREFIX) ? String(file.name) : MANIFEST_PREFIX + file.name;
    const manifest = await getStoredJson(context, path);
    const year = validYear(manifest?.year);
    if (!year || manifest.state !== "DELETED" || known.has(year) || !manifest.summary) continue;
    years.push({
      ...manifest.summary,
      year,
      status: "BACKED_UP",
      backupState: "DELETED",
      recordsSha256: manifest.recordsSha256 || null,
      recordsCount: Number(manifest.recordsCount || 0),
    });
    known.add(year);
  }
  return years.sort((a, b) => String(b.year).localeCompare(String(a.year)));
}
function summarizeYear(rows: Array<{ id: string; record: Record<string, any> }>, year: string): any {
  const jo = new Map<string, { open: boolean }>();
  let totalOrder = 0, totalHasil = 0, totalSisa = 0;
  let openRows = 0, notArchivedRows = 0, h1PendingRows = 0, invalidRows = 0;
  for (const row of rows) {
    const record = row.record;
    const key = String(record.jobOrder || row.id);
    const state = jo.get(key) || { open: false };
    const remaining = remainingQty(record);
    const closed = Number.isFinite(remaining) && remaining <= 0;
    if (!closed) { state.open = true; openRows++; }
    if (!Number.isFinite(remaining)) invalidRows++;
    if (record.isArchived !== true || record.archiveStorage !== "supabase" || record.restoredAt) notArchivedRows++;
    if (!hPlusOnePassed(String(record.tanggal || ""))) h1PendingRows++;
    jo.set(key, state);
    const order = Number(record.order || 0), hasil = Number(record.hasil || 0);
    if (Number.isFinite(order)) totalOrder += order;
    if (Number.isFinite(hasil)) totalHasil += hasil;
    if (Number.isFinite(remaining)) totalSisa += remaining;
  }
  let closedJO = 0, openJO = 0;
  for (const state of jo.values()) state.open ? openJO++ : closedJO++;
  const currentYear = jakartaToday().slice(0, 4);
  const readyRows = rows.filter(({ record }) =>
    isClosed(record) && record.isArchived === true &&
    record.archiveStorage === "supabase" && !record.restoredAt &&
    hPlusOnePassed(String(record.tanggal || ""))
  ).length;
  let status = "WAITING_FINALIZATION";
  if (year === currentYear) status = "RUNNING";
  else if (Number(year) > Number(currentYear)) status = "UPCOMING";
  else if (rows.length > 0 && readyRows === rows.length) status = "FINAL";
  return {
    year, status, totalRecords: rows.length, totalJO: jo.size, closedJO, openJO,
    totalOrder, totalHasil, totalSisa, openRows, readyRows,
    pendingArchiveRows: Math.max(0, rows.length - readyRows),
    notArchivedRows, h1PendingRows, invalidRows,
  };
}
async function getYearRows(year: string) {
  const firebase = await getFirebaseAccessToken();
  const allRows = await listFirestoreRows(firebase);
  const rows = allRows.filter(({ record }) => String(record.tanggal || "").slice(0, 4) === year)
    .sort((a, b) => a.id.localeCompare(b.id));
  return { firebase, rows, summary: summarizeYear(rows, year) };
}
function sameArchiveRecord(current: Record<string, any>, stored: Record<string, any>): boolean {
  const textFields = ["tanggal", "jobOrder", "poNum", "kodeItem", "produk", "ket"];
  const numberFields = ["order", "hasil", "sisa"];
  if (String(stored?.docId || "") !== String(current.docId || "")) return false;
  for (const field of textFields) {
    if (String(current[field] ?? "") !== String(stored[field] ?? "")) return false;
  }
  for (const field of numberFields) {
    const a = Number(current[field] ?? 0), b = Number(stored[field] ?? 0);
    if (!Number.isFinite(a) || !Number.isFinite(b) || a !== b) return false;
  }
  return true;
}
async function buildFinalSnapshot(context: Context, year: string) {
  const result = await getYearRows(year);
  const rows = result.rows;
  if (!rows.length) throw new Error("Tidak ada data pengiriman untuk tahun " + year + ".");
  if (result.summary.status !== "FINAL") {
    throw new Error("Tahun " + year + " belum berstatus FINAL. Masih ada JO OPEN, arsip belum lengkap, atau H+1 belum terlewati.");
  }
  const records: any[] = [];
  for (let offset = 0; offset < rows.length; offset += 20) {
    const group = rows.slice(offset, offset + 20);
    const stored = await Promise.all(group.map(async (row) => ({
      row, envelope: await getStoredJson(context, RECORD_PREFIX + row.id + ".json"),
    })));
    for (const item of stored) {
      if (!item.envelope || item.envelope.archiveState !== "ARCHIVED" ||
          item.envelope.sourceDocId !== item.row.id ||
          !sameArchiveRecord(item.row.record, item.envelope.record || {})) {
        throw new Error("Pemeriksaan arsip gagal pada JO " +
          String(item.row.record.jobOrder || item.row.id) +
          ". File Supabase tidak ditemukan, belum CLOSED, atau datanya tidak sama dengan Firestore.");
      }
      records.push(canonicalize({
        ...item.row.record,
        docId: item.row.id,
        status: "CLOSED",
        archiveState: "ARCHIVED",
        archivedAt: item.envelope.archivedAt || item.row.record.archivedAt || null,
        archivedBy: item.envelope.archivedBy || item.row.record.archivedBy || null,
        sourceCollection: "production_data_v2",
      }));
    }
  }
  records.sort((a, b) => String(a.docId).localeCompare(String(b.docId)));
  const recordsSha256 = await sha256(canonicalJson(records));
  return { firebase: result.firebase, summary: result.summary, records, recordsSha256 };
}
async function deleteStorageRows(context: Context, ids: string[]) {
  if (!ids.length) return;
  const response = await storageRequest(context, "/object/" + BUCKET, {
    method: "DELETE",
    body: JSON.stringify({ prefixes: ids.map((id) => RECORD_PREFIX + id + ".json") }),
  });
  if (!response.ok) {
    const details = await response.text();
    if (/not found|does not exist/i.test(details)) return;
    throw new Error("Gagal menghapus file arsip Supabase (HTTP " + response.status + "): " + details.slice(0, 180));
  }
}
async function deleteFirestoreRows(firebase: { projectId: string; accessToken: string }, ids: string[]) {
  if (!ids.length) return;
  const url = "https://firestore.googleapis.com/v1/projects/" + encodeURIComponent(firebase.projectId) +
    "/databases/(default)/documents:commit";
  const writes = ids.map((id) => ({
    delete: "projects/" + firebase.projectId + "/databases/(default)/documents/production_data_v2/" + id,
  }));
  const response = await fetch(url, {
    method: "POST",
    headers: { Authorization: "Bearer " + firebase.accessToken, "Content-Type": "application/json" },
    body: JSON.stringify({ writes }),
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error("Gagal menghapus dokumen tahun terpilih dari Firestore (HTTP " + response.status + "): " + details.slice(0, 180));
  }
}
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);
  try {
    const input = await req.json();
    const action = String(input?.action || "");
    if (action === "summary") {
      const url = Deno.env.get("SUPABASE_URL") || "";
      const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
      if (!url || !serviceKey) return json({ success: false, error: "Konfigurasi Supabase server belum lengkap." }, 500);
      const context = { url, serviceKey };
      const denied = await authorizeViewer(context, input);
      if (denied) return denied;
      const firebase = await getFirebaseAccessToken();
      const rows = await listFirestoreRows(firebase);
      const byYear = new Map<string, Array<{ id: string; record: Record<string, any> }>>();
      for (const row of rows) {
        const year = String(row.record.tanggal || "").slice(0, 4);
        if (!/^\d{4}$/.test(year)) continue;
        if (!byYear.has(year)) byYear.set(year, []);
        byYear.get(year)!.push(row);
      }
      const currentYear = jakartaToday().slice(0, 4);
      if (!byYear.has(currentYear)) byYear.set(currentYear, []);
      let summaries = Array.from(byYear.entries())
        .map(([year, yearRows]) => summarizeYear(yearRows, year));
      summaries = await mergeDeletedAnnualSummaries(context, summaries);
      return json({ success: true, years: summaries, grouping: "delivery_date_year" });
    }

    if (action === "admin-summary") {
      const authorizedSummary = await authorizeAdmin(req);
      if (authorizedSummary instanceof Response) return authorizedSummary;
      const firebase = await getFirebaseAccessToken();
      const rows = await listFirestoreRows(firebase);
      const byYear = new Map<string, Array<{ id: string; record: Record<string, any> }>>();
      for (const row of rows) {
        const rowYear = String(row.record.tanggal || "").slice(0, 4);
        if (!/^\\d{4}$/.test(rowYear)) continue;
        if (!byYear.has(rowYear)) byYear.set(rowYear, []);
        byYear.get(rowYear)!.push(row);
      }
      const currentYear = jakartaToday().slice(0, 4);
      if (!byYear.has(currentYear)) byYear.set(currentYear, []);
      let years = Array.from(byYear.entries())
        .map(([rowYear, yearRows]) => summarizeYear(yearRows, rowYear));
      years = await mergeDeletedAnnualSummaries({ url: Deno.env.get("SUPABASE_URL") || "", serviceKey: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "" }, years);
      return json({ success: true, years, grouping: "delivery_date_year" });
    }

    const authorized = await authorizeAdmin(req);
    if (authorized instanceof Response) return authorized;
    const context = authorized.context;
    const profile = authorized.profile;
    const year = validYear(input?.year);
    if (!year) return json({ success: false, error: "Tahun harus diisi dalam format YYYY." }, 400);

    if (action === "export") {
      const snapshot = await buildFinalSnapshot(context, year);
      const backup = {
        schemaVersion: 1,
        backupType: "ASSEMBLY_ANNUAL_SHIPMENT_BACKUP",
        year,
        grouping: "delivery_date_year",
        generatedAt: new Date().toISOString(),
        generatedBy: profile.username,
        source: { firestoreCollection: "production_data_v2", supabaseBucket: BUCKET },
        summary: snapshot.summary,
        integrity: {
          algorithm: "SHA-256",
          recordsSha256: snapshot.recordsSha256,
          recordsCount: snapshot.records.length,
        },
        records: snapshot.records,
      };
      return json({ success: true, backup });
    }

    if (action === "verify") {
      const expectedHash = String(input?.recordsSha256 || "").toLowerCase();
      const expectedCount = Number(input?.recordsCount);
      if (!/^[a-f0-9]{64}$/.test(expectedHash) || !Number.isSafeInteger(expectedCount) || expectedCount < 1) {
        return json({ success: false, error: "Informasi checksum atau jumlah baris backup tidak valid." }, 400);
      }
      const snapshot = await buildFinalSnapshot(context, year);
      if (snapshot.recordsSha256 !== expectedHash || snapshot.records.length !== expectedCount) {
        return json({ success: false, error: "Verifikasi gagal. Isi file backup tidak sama dengan data cloud saat ini." }, 409);
      }
      const manifest = {
        schemaVersion: 1,
        year,
        state: "VERIFIED",
        grouping: "delivery_date_year",
        recordsSha256: snapshot.recordsSha256,
        recordsCount: snapshot.records.length,
        summary: snapshot.summary,
        verifiedAt: new Date().toISOString(),
        verifiedBy: profile.username,
      };
      await putStoredJson(context, MANIFEST_PREFIX + year + ".json", manifest);
      return json({ success: true, state: manifest.state, manifest });
    }

    if (action === "manifest") {
      const manifest = await getStoredJson(context, MANIFEST_PREFIX + year + ".json");
      return json({ success: true, manifest: manifest || null });
    }

    if (action === "purge") {
      const confirmation = String(input?.confirmYear || "");
      const expectedHash = String(input?.recordsSha256 || "").toLowerCase();
      if (confirmation !== year || !/^[a-f0-9]{64}$/.test(expectedHash)) {
        return json({ success: false, error: "Konfirmasi tahun dan checksum wajib cocok." }, 400);
      }
      let manifest = await getStoredJson(context, MANIFEST_PREFIX + year + ".json");
      if (!manifest || !["VERIFIED", "PURGING"].includes(manifest.state) ||
          manifest.recordsSha256 !== expectedHash) {
        return json({ success: false, error: "Backup tahun ini belum diverifikasi atau checksum tidak cocok." }, 409);
      }
      const firebase = await getFirebaseAccessToken();
      if (manifest.state === "VERIFIED") {
        const snapshot = await buildFinalSnapshot(context, year);
        if (snapshot.recordsSha256 !== expectedHash ||
            snapshot.records.length !== Number(manifest.recordsCount)) {
          return json({ success: false, error: "Data cloud berubah setelah verifikasi backup. Unduh dan verifikasi ulang sebelum penghapusan." }, 409);
        }
        manifest = {
          ...manifest,
          state: "PURGING",
          targetIds: snapshot.records.map((record) => String(record.docId)),
          nextIndex: 0,
          purgeStartedAt: new Date().toISOString(),
          purgeStartedBy: profile.username,
        };
        await putStoredJson(context, MANIFEST_PREFIX + year + ".json", manifest);
      }
      const ids: string[] = Array.isArray(manifest.targetIds) ? manifest.targetIds : [];
      const start = Math.max(0, Number(manifest.nextIndex || 0));
      const batch = ids.slice(start, start + PURGE_BATCH_SIZE);
      if (batch.length) {
        await deleteStorageRows(context, batch);
        await deleteFirestoreRows(firebase, batch);
      }
      const nextIndex = start + batch.length;
      const done = nextIndex >= ids.length;
      manifest = {
        ...manifest,
        state: done ? "DELETED" : "PURGING",
        nextIndex,
        purgeUpdatedAt: new Date().toISOString(),
        ...(done ? {
          deletedAt: new Date().toISOString(),
          deletedBy: profile.username,
          deletedRecords: ids.length,
          targetIds: undefined,
        } : {}),
      };
      await putStoredJson(context, MANIFEST_PREFIX + year + ".json", manifest);
      return json({
        success: true,
        state: manifest.state,
        deletedThisBatch: batch.length,
        deletedRecords: nextIndex,
        totalRecords: ids.length,
        hasMore: !done,
      });
    }

    return json({ success: false, error: "Aksi backup tahunan tidak dikenal." }, 400);
  } catch (error) {
    console.error("annual-shipment-archive", error);
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Proses backup tahunan gagal.",
    }, 500);
  }
});
