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

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);
  try {
    const input = await req.json();
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
