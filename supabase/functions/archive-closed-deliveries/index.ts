// Supabase-backed archive for CLOSED Assembly delivery rows.
// Full records are stored in private Storage bucket "arsip-pengiriman".
// H+1 must have ended in Asia/Jakarta. A row dated H becomes eligible at 00:00 WIB on H+2.

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

const BUCKET = "arsip-pengiriman";
const PREFIX = "records/";
const MAX_BATCH = 400;
const MAX_LIST = 5000;

function jakartaToday(): string {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Jakarta", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(new Date());
  const get = (type: string) => parts.find((part) => part.type === type)?.value || "";
  return get("year") + "-" + get("month") + "-" + get("day");
}

function addDays(dateString: string, days: number): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateString)) return "";
  const parts = dateString.split("-").map(Number);
  const year = parts[0], month = parts[1], day = parts[2];
  const input = new Date(Date.UTC(year, month - 1, day));
  if (input.getUTCFullYear() !== year || input.getUTCMonth() !== month - 1 || input.getUTCDate() !== day) return "";
  const result = new Date(Date.UTC(year, month - 1, day + days));
  return result.getUTCFullYear() + "-" +
    String(result.getUTCMonth() + 1).padStart(2, "0") + "-" +
    String(result.getUTCDate()).padStart(2, "0");
}

function remainingQty(record: Record<string, any>): number {
  if (record.sisa !== undefined && record.sisa !== null && String(record.sisa).trim() !== "") {
    const value = Number(record.sisa);
    return Number.isFinite(value) ? value : Number.NaN;
  }
  const order = Number(record.order), actual = Number(record.hasil);
  return Number.isFinite(order) && Number.isFinite(actual) ? order - actual : Number.NaN;
}

function eligibilityError(record: Record<string, any>): string | null {
  if (!record || typeof record !== "object" || Array.isArray(record)) return "Format data pengiriman tidak valid.";
  const date = String(record.tanggal || "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return "Tanggal pengiriman tidak valid.";
  const remaining = remainingQty(record);
  if (!Number.isFinite(remaining) || remaining > 0) return "Baris masih OPEN atau nilai sisa tidak valid.";
  const hPlusOne = addDays(date, 1);
  if (!hPlusOne) return "Tanggal pengiriman tidak valid.";
  if (jakartaToday() <= hPlusOne) {
    return "Belum melewati H+1. Arsip tersedia mulai " + addDays(hPlusOne, 1) + " pukul 00.00 WIB.";
  }
  return null;
}

function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

async function authorize(req: Request) {
  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const bearer = req.headers.get("Authorization") || "";
  const accessToken = bearer.startsWith("Bearer ") ? bearer.slice(7) : "";
  if (!url || !anonKey || !serviceKey) {
    return { error: json({ success: false, error: "Konfigurasi Supabase server belum lengkap." }, 500) };
  }
  if (!accessToken) return { error: json({ success: false, error: "Sesi Supabase diperlukan." }, 401) };

  const authResponse = await fetch(url + "/auth/v1/user", {
    headers: { apikey: anonKey, Authorization: "Bearer " + accessToken },
  });
  if (!authResponse.ok) {
    return { error: json({ success: false, error: "Sesi Supabase tidak valid atau sudah berakhir." }, 401) };
  }
  const authUser = await authResponse.json();
  if (!authUser || !authUser.id) return { error: json({ success: false, error: "Pengguna tidak dapat diverifikasi." }, 401) };

  const profileUrl = new URL(url + "/rest/v1/assembly_users");
  profileUrl.searchParams.set("user_id", "eq." + authUser.id);
  profileUrl.searchParams.set("select", "username,full_name,role,is_active");
  const profileResponse = await fetch(profileUrl, {
    headers: { apikey: serviceKey, Authorization: "Bearer " + serviceKey },
  });
  if (!profileResponse.ok) return { error: json({ success: false, error: "Profil Assembly gagal diverifikasi." }, 503) };
  const profiles = await profileResponse.json();
  const profile = profiles && profiles[0];
  if (!profile || profile.is_active !== true || !["admin", "superuser"].includes(profile.role)) {
    return { error: json({ success: false, error: "Akun tidak aktif atau tidak berhak mengelola arsip." }, 403) };
  }
  return { url, serviceKey, profile };
}

async function storageRequest(context: { url: string; serviceKey: string }, path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("apikey", context.serviceKey);
  headers.set("Authorization", "Bearer " + context.serviceKey);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return await fetch(context.url + "/storage/v1" + path, { ...init, headers });
}

async function ensurePrivateBucket(context: { url: string; serviceKey: string }) {
  const check = await storageRequest(context, "/bucket/" + BUCKET);
  if (check.ok) {
    const update = await storageRequest(context, "/bucket/" + BUCKET, {
      method: "PUT", body: JSON.stringify({ public: false }),
    });
    if (!update.ok) throw new Error("Bucket arsip ditemukan tetapi gagal dipastikan private.");
    return;
  }
  if (check.status !== 404) throw new Error("Tidak dapat memeriksa bucket arsip Supabase.");
  const create = await storageRequest(context, "/bucket", {
    method: "POST",
    body: JSON.stringify({
      id: BUCKET, name: BUCKET, public: false,
      file_size_limit: 52428800, allowed_mime_types: ["application/json"],
    }),
  });
  if (!create.ok && create.status !== 409) {
    const details = await create.text();
    throw new Error("Gagal membuat private bucket arsip: " + details.slice(0, 250));
  }
}

async function getStoredRecord(context: { url: string; serviceKey: string }, path: string) {
  const response = await storageRequest(context, "/object/" + BUCKET + "/" + encodePath(path));
  if (response.status === 404) return null;

  // Supabase Storage pada beberapa respons mengirim "Object not found"
  // sebagai HTTP 400, bukan 404. Itu berarti file baru belum ada, bukan kegagalan baca.
  if (response.status === 400) {
    const details = await response.text();
    let message = details;
    try {
      const parsed = JSON.parse(details);
      message = String(parsed.message || parsed.error || parsed.error_description || details);
    } catch (_) {}
    if (/object\s+not\s+found|not\s+found/i.test(message)) return null;
    throw new Error("Gagal membaca file arsip yang sudah ada: " + message.slice(0, 200));
  }

  if (!response.ok) {
    const details = await response.text();
    throw new Error("Gagal membaca file arsip yang sudah ada (HTTP " + response.status + "): " + details.slice(0, 200));
  }
  return await response.json();
}

async function putStoredRecord(context: { url: string; serviceKey: string }, path: string, payload: unknown) {
  const response = await storageRequest(context, "/object/" + BUCKET + "/" + encodePath(path), {
    method: "POST", headers: { "x-upsert": "true" }, body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error("Gagal menyimpan file ke Supabase Storage: " + details.slice(0, 250));
  }
}

async function listStorageObjects(context: { url: string; serviceKey: string }) {
  const output: any[] = [];
  for (let offset = 0; offset < MAX_LIST; offset += 1000) {
    const response = await storageRequest(context, "/object/list/" + BUCKET, {
      method: "POST",
      body: JSON.stringify({
        prefix: PREFIX, limit: 1000, offset,
        sortBy: { column: "created_at", order: "desc" },
      }),
    });
    if (!response.ok) {
      const details = await response.text();
      throw new Error("Gagal membaca daftar arsip Supabase: " + details.slice(0, 250));
    }
    const batch = await response.json();
    if (!Array.isArray(batch)) throw new Error("Respons daftar arsip Supabase tidak valid.");
    output.push(...batch.filter((item: any) => item && typeof item.name === "string" && item.name.endsWith(".json")));
    if (batch.length < 1000) return output;
  }
  throw new Error("Jumlah file arsip melewati batas pembacaan 5.000 file.");
}

async function listArchives(context: { url: string; serviceKey: string }) {
  const files = await listStorageObjects(context);
  const records: any[] = [];
  for (let i = 0; i < files.length; i += 20) {
    const group = files.slice(i, i + 20);
    const results = await Promise.all(group.map(async (file: any) => {
      const path = file.name.startsWith(PREFIX) ? file.name : PREFIX + file.name;
      const envelope = await getStoredRecord(context, path);
      if (!envelope || envelope.archiveState === "RESTORED" || !envelope.record) return null;
      return {
        ...envelope.record,
        sourceDocId: envelope.sourceDocId,
        archivePath: path,
        archivedAt: envelope.archivedAt,
        archivedBy: envelope.archivedBy,
        archiveState: envelope.archiveState || "ARCHIVED",
      };
    }));
    records.push(...results.filter(Boolean));
  }
  records.sort((a, b) => String(b.archivedAt || "").localeCompare(String(a.archivedAt || "")));
  return records;
}



type SupabaseArchiveContext = { url: string; serviceKey: string };

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
  if ("geoPointValue" in value) return value.geoPointValue;
  if ("arrayValue" in value) {
    return (value.arrayValue?.values || []).map(firestoreValueToJs);
  }
  if ("mapValue" in value) {
    return firestoreFieldsToJs(value.mapValue?.fields || {});
  }
  return null;
}

function firestoreFieldsToJs(fields: Record<string, any>): Record<string, any> {
  const output: Record<string, any> = {};
  for (const [key, value] of Object.entries(fields || {})) {
    output[key] = firestoreValueToJs(value);
  }
  return output;
}

async function getFirebaseAccessToken(): Promise<{ projectId: string; accessToken: string }> {
  const raw = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON");
  if (!raw) throw new Error("Secret FIREBASE_SERVICE_ACCOUNT_JSON belum dipasang pada Supabase Edge Functions.");
  let account: any;
  try {
    account = JSON.parse(raw);
  } catch (_) {
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
  const keyBody = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const keyBytes = Uint8Array.from(atob(keyBody), (char) => char.charCodeAt(0));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    keyBytes,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(unsignedJwt),
  );
  const assertion = unsignedJwt + "." + base64UrlEncode(new Uint8Array(signature));
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const tokenResult = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !tokenResult.access_token) {
    throw new Error("Gagal memperoleh akses Firestore dari Google: " +
      String(tokenResult.error_description || tokenResult.error || "OAuth gagal.").slice(0, 200));
  }
  return { projectId: String(account.project_id), accessToken: String(tokenResult.access_token) };
}

async function listFirestoreShipmentDocuments(firebase: { projectId: string; accessToken: string }) {
  const documents: Array<{ name: string; id: string; record: Record<string, any> }> = [];
  let pageToken = "";
  const baseUrl = "https://firestore.googleapis.com/v1/projects/" +
    encodeURIComponent(firebase.projectId) +
    "/databases/(default)/documents/production_data_v2";

  do {
    const url = new URL(baseUrl);
    url.searchParams.set("pageSize", "1000");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await fetch(url, {
      headers: { Authorization: "Bearer " + firebase.accessToken },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error("Gagal membaca production_data_v2 dari Firestore: HTTP " +
        response.status + " " + String(payload.error?.message || "").slice(0, 180));
    }
    for (const item of payload.documents || []) {
      const name = String(item.name || "");
      const id = name.split("/").pop() || "";
      if (!id) continue;
      documents.push({ name, id, record: { ...firestoreFieldsToJs(item.fields || {}), docId: id } });
    }
    pageToken = String(payload.nextPageToken || "");
    if (documents.length > 20000) {
      throw new Error("Jumlah dokumen Firestore melebihi batas aman 20.000 untuk satu siklus arsip.");
    }
  } while (pageToken);

  return documents;
}

async function markFirestoreShipmentArchived(
  firebase: { accessToken: string },
  documentName: string,
  archivedAt: string,
) {
  const url = new URL("https://firestore.googleapis.com/v1/" + documentName);
  for (const field of ["isArchived", "archivedAt", "archivedBy", "archiveStatus", "archiveStorage"]) {
    url.searchParams.append("updateMask.fieldPaths", field);
  }
  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: "Bearer " + firebase.accessToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      fields: {
        isArchived: { booleanValue: true },
        archivedAt: { timestampValue: archivedAt },
        archivedBy: { stringValue: "system-scheduler" },
        archiveStatus: { stringValue: "CLOSED" },
        archiveStorage: { stringValue: "supabase" },
      },
    }),
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error("File sudah di Supabase tetapi metadata Firestore gagal diperbarui (HTTP " +
      response.status + "): " + details.slice(0, 180));
  }
}

function validCronSecret(provided: string, expected: string): boolean {
  if (!provided || !expected || provided.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return mismatch === 0;
}

async function runScheduledArchive(context: SupabaseArchiveContext) {
  const firebase = await getFirebaseAccessToken();
  await ensurePrivateBucket(context);
  const documents = await listFirestoreShipmentDocuments(firebase);
  const summary = {
    success: true,
    scanned: documents.length,
    archived: 0,
    alreadyArchived: 0,
    skippedAlreadyMarked: 0,
    skippedOpen: 0,
    skippedH1: 0,
    skippedRestored: 0,
    failed: 0,
    dateWib: jakartaToday(),
    errors: [] as string[],
  };

  const candidates = documents.filter(({ record }) => record.isArchived !== true);
  for (let offset = 0; offset < candidates.length; offset += 10) {
    const group = candidates.slice(offset, offset + 10);
    const results = await Promise.all(group.map(async ({ name, id, record }) => {
      try {
        // A manual restore is an explicit request to return this JO to the active list.
        // Do not immediately re-archive it on the next scheduled cycle.
        if (record.restoredAt) return "skippedRestored";

        const remaining = remainingQty(record);
        if (!Number.isFinite(remaining)) {
          throw new Error("Nilai sisa/order/hasil tidak valid.");
        }
        if (remaining > 0) return "skippedOpen";
        if (!isHPlusOnePassedForServer(record.tanggal)) return "skippedH1";
        const reason = eligibilityError(record);
        if (reason) throw new Error(reason);

        const path = PREFIX + id + ".json";
        const existing = await getStoredRecord(context, path);
        let archivedAt = "";
        if (existing && existing.archiveState !== "RESTORED") {
          archivedAt = String(existing.archivedAt || new Date().toISOString());
          await markFirestoreShipmentArchived(firebase, name, archivedAt);
          return "alreadyArchived";
        }

        archivedAt = new Date().toISOString();
        await putStoredRecord(context, path, {
          schemaVersion: 1,
          sourceCollection: "production_data_v2",
          sourceDocId: id,
          archiveState: "ARCHIVED",
          archivedAt,
          archivedBy: "system-scheduler",
          deliveryDate: record.tanggal,
          hPlusOneDate: addDays(String(record.tanggal), 1),
          record,
        });
        // Source Firestore document is retained; only archive metadata is updated
        // after the private Storage write succeeds.
        await markFirestoreShipmentArchived(firebase, name, archivedAt);
        return "archived";
      } catch (error) {
        return { failed: id + " (" + String(record.jobOrder || "-") + "): " +
          (error instanceof Error ? error.message : "Kesalahan tidak diketahui.") };
      }
    }));

    for (const result of results) {
      if (result === "archived") summary.archived++;
      else if (result === "alreadyArchived") summary.alreadyArchived++;
      else if (result === "skippedOpen") summary.skippedOpen++;
      else if (result === "skippedH1") summary.skippedH1++;
      else if (result === "skippedRestored") summary.skippedRestored++;
      else if (typeof result === "object" && result && "failed" in result) {
        summary.failed++;
        if (summary.errors.length < 20) summary.errors.push(result.failed);
      }
    }
  }
  return summary;
}

function isHPlusOnePassedForServer(dateValue: unknown): boolean {
  const hPlusOne = addDays(String(dateValue || ""), 1);
  return !!hPlusOne && jakartaToday() > hPlusOne;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);
  try {
    const input = await req.json();

    if (input.action === "scheduled-archive") {
      const expectedSecret = Deno.env.get("ARCHIVE_CRON_SECRET") || "";
      const providedSecret = req.headers.get("x-archive-cron-secret") || "";
      if (!validCronSecret(providedSecret, expectedSecret)) {
        return json({ success: false, error: "Scheduler tidak terotorisasi." }, 401);
      }
      const url = Deno.env.get("SUPABASE_URL");
      const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
      if (!url || !serviceKey) {
        return json({ success: false, error: "Konfigurasi Supabase server belum lengkap." }, 500);
      }
      const result = await runScheduledArchive({ url, serviceKey });
      return json(result);
    }

    const auth = await authorize(req);
    if (!("url" in auth) || !("serviceKey" in auth) || !("profile" in auth)) {
      if ("error" in auth && auth.error instanceof Response) return auth.error;
      return json({ success: false, error: "Otorisasi arsip gagal." }, 401);
    }
    const context = auth as { url: string; serviceKey: string; profile: any };
    await ensurePrivateBucket(context);

    if (input.action === "list") {
      const rows = await listArchives(context);
      return json({ success: true, bucket: BUCKET, count: rows.length, records: rows });
    }

    if (input.action === "audit") {
      if (!Array.isArray(input.records) || input.records.length < 1 || input.records.length > MAX_BATCH) {
        return json({ success: false, error: "Maksimal " + MAX_BATCH + " baris per pemeriksaan." }, 400);
      }
      const matched: any[] = [];
      const missing: any[] = [];
      const mismatched: any[] = [];
      const invalid: any[] = [];
      const textFields = ["tanggal", "jobOrder", "poNum", "kodeItem", "produk", "ket"];
      const numberFields = ["order", "hasil", "sisa"];

      for (const entry of input.records) {
        const id = typeof entry?.sourceDocId === "string" ? entry.sourceDocId : "";
        const data = entry?.data;
        if (!/^[A-Za-z0-9_-]{3,80}$/.test(id) || !data || data.docId !== id) {
          invalid.push({ sourceDocId: id || "-", reason: "Identitas dokumen dari Firestore tidak valid." });
          continue;
        }

        const envelope = await getStoredRecord(context, PREFIX + id + ".json");
        if (!envelope) {
          missing.push({ sourceDocId: id, jobOrder: String(data.jobOrder || "-") });
          continue;
        }

        const fields: string[] = [];
        if (envelope.sourceDocId !== id || envelope.record?.docId !== id) {
          fields.push("sourceDocId");
        }
        for (const field of textFields) {
          const firestoreValue = String(data[field] ?? "");
          const supabaseValue = String(envelope.record?.[field] ?? "");
          if (firestoreValue !== supabaseValue) fields.push(field);
        }
        for (const field of numberFields) {
          const firestoreValue = Number(data[field] ?? 0);
          const supabaseValue = Number(envelope.record?.[field] ?? 0);
          if (!Number.isFinite(firestoreValue) || !Number.isFinite(supabaseValue) ||
              firestoreValue !== supabaseValue) fields.push(field);
        }

        if (fields.length) {
          mismatched.push({ sourceDocId: id, jobOrder: String(data.jobOrder || "-"), fields });
        } else {
          matched.push({ sourceDocId: id, jobOrder: String(data.jobOrder || "-") });
        }
      }

      return json({
        success: true,
        bucket: BUCKET,
        total: input.records.length,
        matched,
        missing,
        mismatched,
        invalid,
      });
    }

    if (input.action === "archive") {
      if (!Array.isArray(input.records) || input.records.length < 1 || input.records.length > MAX_BATCH) {
        return json({ success: false, error: "Maksimal " + MAX_BATCH + " baris per proses arsip." }, 400);
      }
      const archived: any[] = [];
      const alreadyArchived: any[] = [];
      for (const entry of input.records) {
        const id = typeof entry?.sourceDocId === "string" ? entry.sourceDocId : "";
        const record = entry?.data;
        if (!/^[A-Za-z0-9_-]{3,80}$/.test(id) || !record || record.docId !== id) {
          return json({ success: false, error: "Identitas dokumen arsip tidak valid." }, 400);
        }
        const reason = eligibilityError(record);
        if (reason) {
          return json({ success: false, error: "JO " + (record.jobOrder || id) + ": " + reason }, 409);
        }
        const path = PREFIX + id + ".json";
        const existing = await getStoredRecord(context, path);
        if (existing && existing.archiveState !== "RESTORED") {
          alreadyArchived.push({ sourceDocId: id, archivePath: path });
          continue;
        }
        await putStoredRecord(context, path, {
          schemaVersion: 1,
          sourceCollection: "production_data_v2",
          sourceDocId: id,
          archiveState: "ARCHIVED",
          archivedAt: new Date().toISOString(),
          archivedBy: context.profile.username,
          deliveryDate: record.tanggal,
          hPlusOneDate: addDays(String(record.tanggal), 1),
          record,
        });
        archived.push({ sourceDocId: id, archivePath: path });
      }
      return json({
        success: true, bucket: BUCKET, archived, alreadyArchived,
        total: archived.length + alreadyArchived.length,
      });
    }

    if (input.action === "restore") {
      const id = typeof input.sourceDocId === "string" ? input.sourceDocId : "";
      if (!/^[A-Za-z0-9_-]{3,80}$/.test(id)) {
        return json({ success: false, error: "ID dokumen untuk pemulihan tidak valid." }, 400);
      }
      const path = PREFIX + id + ".json";
      const existing = await getStoredRecord(context, path);
      if (!existing || existing.archiveState === "RESTORED") {
        return json({ success: false, error: "Arsip tidak ditemukan atau sudah dipulihkan." }, 404);
      }
      existing.archiveState = "RESTORED";
      existing.restoredAt = new Date().toISOString();
      existing.restoredBy = context.profile.username;
      await putStoredRecord(context, path, existing);
      return json({ success: true, sourceDocId: id, archiveState: "RESTORED" });
    }

    return json({ success: false, error: "Aksi arsip tidak dikenal." }, 400);
  } catch (error) {
    console.error("archive-closed-deliveries", error);
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Permintaan arsip gagal diproses.",
    }, 500);
  }
});
