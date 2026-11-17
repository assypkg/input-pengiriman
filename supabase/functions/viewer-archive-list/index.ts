// Paginated read-only archive endpoint for the corporate Summary Viewer.
// The browser never receives the Supabase service-role key or direct Storage access.
// Each request validates the existing Firestore Viewer token and registered device first.

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
const LIST_BATCH = 100;
const MAX_SCAN_PER_REQUEST = 500;
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 50;

type StorageContext = { url: string; serviceKey: string };

function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

function validIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day;
}

async function validateViewerToken(
  url: string,
  serviceKey: string,
  token: string,
  deviceId: string,
): Promise<Response | null> {
  const response = await fetch(url + "/functions/v1/validate-viewer-token", {
    method: "POST",
    headers: {
      apikey: serviceKey,
      Authorization: "Bearer " + serviceKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token, deviceId }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success !== true) {
    return json({
      success: false,
      error: payload.message || "Akses arsip ditolak. Periksa token dan perangkat Viewer.",
    }, response.status >= 400 ? response.status : 403);
  }
  return null;
}

async function storageRequest(context: StorageContext, path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("apikey", context.serviceKey);
  headers.set("Authorization", "Bearer " + context.serviceKey);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return await fetch(context.url + "/storage/v1" + path, { ...init, headers });
}

async function listStorageObjects(context: StorageContext, offset: number, limit: number) {
  const response = await storageRequest(context, "/object/list/" + BUCKET, {
    method: "POST",
    body: JSON.stringify({
      prefix: PREFIX,
      limit,
      offset,
      sortBy: { column: "created_at", order: "desc" },
    }),
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error("Gagal membaca daftar file arsip Supabase: " + details.slice(0, 220));
  }
  const result = await response.json();
  if (!Array.isArray(result)) throw new Error("Format daftar file arsip Supabase tidak valid.");
  return result.filter((item: any) =>
    item && typeof item.name === "string" && item.name.endsWith(".json")
  );
}

async function getStoredRecord(context: StorageContext, path: string) {
  const response = await storageRequest(
    context,
    "/object/" + BUCKET + "/" + encodePath(path),
  );
  if (response.status === 404) return null;
  if (response.status === 400) {
    const details = await response.text();
    let message = details;
    try {
      const payload = JSON.parse(details);
      message = String(payload.message || payload.error || details);
    } catch (_) {}
    if (/object\s+not\s+found|not\s+found/i.test(message)) return null;
    throw new Error("Gagal membaca file arsip: " + message.slice(0, 180));
  }
  if (!response.ok) {
    const details = await response.text();
    throw new Error("Gagal membaca file arsip (HTTP " + response.status + "): " + details.slice(0, 180));
  }
  return await response.json();
}

function recordMatches(
  record: any,
  keyword: string,
  deliveryDateFrom: string,
  deliveryDateTo: string,
): boolean {
  if (!record || typeof record !== "object") return false;
  const deliveryDate = String(record.tanggal || "");
  if (deliveryDateFrom && deliveryDate < deliveryDateFrom) return false;
  if (deliveryDateTo && deliveryDate > deliveryDateTo) return false;
  if (!keyword) return true;
  const searchable = [
    record.jobOrder,
    record.poNum,
    record.kodeItem,
    record.produk,
    record.tanggal,
    record.ket,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return searchable.includes(keyword);
}

async function calculateArchiveSummary(
  context: StorageContext,
  keyword: string,
  deliveryDateFrom: string,
  deliveryDateTo: string,
) {
  const MAX_SUMMARY_SCAN = 5000;
  let offset = 0;
  let totalClosed = 0;
  let totalHasil = 0;
  let scanned = 0;

  while (scanned < MAX_SUMMARY_SCAN) {
    const requested = Math.min(LIST_BATCH, MAX_SUMMARY_SCAN - scanned);
    const objects = await listStorageObjects(context, offset, requested);
    if (!objects.length) break;

    for (let start = 0; start < objects.length; start += 20) {
      const group = objects.slice(start, start + 20);
      const envelopes = await Promise.all(group.map(async (file: any) => {
        const path = String(file.name).startsWith(PREFIX) ? String(file.name) : PREFIX + String(file.name);
        return await getStoredRecord(context, path);
      }));

      for (const envelope of envelopes) {
        scanned++;
        if (!envelope || envelope.archiveState === "RESTORED" || !envelope.record) continue;
        if (!recordMatches(envelope.record, keyword, deliveryDateFrom, deliveryDateTo)) continue;
        totalClosed++;
        const hasil = Number(envelope.record.hasil || 0);
        if (Number.isFinite(hasil)) totalHasil += hasil;
      }
    }

    offset += objects.length;
    if (objects.length < requested) break;
  }

  if (scanned >= MAX_SUMMARY_SCAN) {
    const nextObjects = await listStorageObjects(context, offset, 1);
    if (nextObjects.length) {
      throw new Error("Jumlah file arsip melebihi batas 5.000 untuk perhitungan KPI. Gunakan filter tanggal yang lebih spesifik.");
    }
  }

  return { totalClosed, totalHasil, scanned };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);

  try {
    const input = await req.json();
    const token = typeof input?.token === "string" ? input.token.trim().toUpperCase() : "";
    const deviceId = typeof input?.deviceId === "string" ? input.deviceId : "";
    const keyword = typeof input?.search === "string" ? input.search.trim().toLowerCase() : "";
    const legacyDeliveryDate = typeof input?.deliveryDate === "string" ? input.deliveryDate.trim() : "";
    const deliveryDateFrom = typeof input?.deliveryDateFrom === "string"
      ? input.deliveryDateFrom.trim() : legacyDeliveryDate;
    const deliveryDateTo = typeof input?.deliveryDateTo === "string"
      ? input.deliveryDateTo.trim() : legacyDeliveryDate;
    const action = typeof input?.action === "string" ? input.action : "list";
    const cursorValue = input?.cursor === undefined || input?.cursor === null ? 0 : Number(input.cursor);
    const pageSizeValue = input?.limit === undefined ? DEFAULT_PAGE_SIZE : Number(input.limit);

    if (!token || token.length > 120 ||
        !/^[A-Za-z0-9_-]{3,80}$/.test(deviceId) ||
        keyword.length > 100 ||
        !["list", "summary"].includes(action) ||
        (deliveryDateFrom && !validIsoDate(deliveryDateFrom)) ||
        (deliveryDateTo && !validIsoDate(deliveryDateTo)) ||
        (deliveryDateFrom && deliveryDateTo && deliveryDateFrom > deliveryDateTo) ||
        !Number.isSafeInteger(cursorValue) || cursorValue < 0 || cursorValue > 1000000 ||
        !Number.isInteger(pageSizeValue) || pageSizeValue < 1 || pageSizeValue > MAX_PAGE_SIZE) {
      return json({ success: false, error: "Parameter pencarian atau identitas Viewer tidak valid." }, 400);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !serviceKey) {
      return json({ success: false, error: "Konfigurasi penyimpanan arsip belum lengkap." }, 500);
    }

    const denied = await validateViewerToken(url, serviceKey, token, deviceId);
    if (denied) return denied;

    const context: StorageContext = { url, serviceKey };

    if (action === "summary") {
      const summary = await calculateArchiveSummary(
        context, keyword, deliveryDateFrom, deliveryDateTo,
      );
      return json({
        success: true,
        bucket: BUCKET,
        ...summary,
        deliveryDateFrom: deliveryDateFrom || null,
        deliveryDateTo: deliveryDateTo || null,
      });
    }

    let offset = cursorValue;
    let scanned = 0;
    let reachedEnd = false;
    let foundNextMatch = false;
    const records: any[] = [];

    while (scanned < MAX_SCAN_PER_REQUEST && !reachedEnd && !foundNextMatch) {
      const requested = Math.min(LIST_BATCH, MAX_SCAN_PER_REQUEST - scanned);
      const objects = await listStorageObjects(context, offset, requested);
      if (!objects.length) {
        reachedEnd = true;
        break;
      }

      for (let start = 0; start < objects.length && !foundNextMatch; start += 20) {
        const group = objects.slice(start, start + 20);
        const groupStartOffset = offset + start;
        const envelopes = await Promise.all(group.map(async (file: any) => {
          const path = String(file.name).startsWith(PREFIX) ? String(file.name) : PREFIX + String(file.name);
          return await getStoredRecord(context, path);
        }));

        for (let index = 0; index < group.length; index++) {
          const envelope = envelopes[index];
          const currentOffset = groupStartOffset + index;
          scanned++;

          if (envelope && envelope.archiveState !== "RESTORED" && envelope.record &&
              recordMatches(envelope.record, keyword, deliveryDateFrom, deliveryDateTo)) {
            if (records.length >= pageSizeValue) {
              // Do not consume the first match for the next page.
              offset = currentOffset;
              foundNextMatch = true;
              break;
            }
            records.push({
              ...envelope.record,
              sourceDocId: envelope.sourceDocId,
              archivePath: PREFIX + envelope.sourceDocId + ".json",
              archivedAt: envelope.archivedAt,
              archivedBy: envelope.archivedBy,
              archiveState: envelope.archiveState || "ARCHIVED",
            });
          }
          offset = currentOffset + 1;
        }
      }

      if (!foundNextMatch && objects.length < requested) reachedEnd = true;
    }

    let hasMore = foundNextMatch;
    if (!reachedEnd && !foundNextMatch) {
      const nextObjects = await listStorageObjects(context, offset, 1);
      hasMore = nextObjects.length > 0;
      if (!hasMore) reachedEnd = true;
    }

    return json({
      success: true,
      bucket: BUCKET,
      records,
      limit: pageSizeValue,
      cursor: cursorValue,
      nextCursor: hasMore ? offset : null,
      hasMore,
      scanned,
      filtered: Boolean(keyword || deliveryDateFrom || deliveryDateTo),
    });
  } catch (error) {
    console.error("viewer-archive-list", error);
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Arsip tidak dapat dimuat.",
    }, 503);
  }
});
