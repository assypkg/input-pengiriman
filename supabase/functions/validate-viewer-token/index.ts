// Validate the existing corporate Viewer token using Firebase's Firestore REST API.
// This mirrors monitoring-pengiriman's validateSchedule + device registration rules.
// Required Edge Function secret: FIREBASE_SERVICE_ACCOUNT_JSON
// Uses Supabase's reserved SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY only server-side.

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

async function getGoogleAccessToken(serviceAccount: any): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = base64url(JSON.stringify({
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  }));
  const unsigned = `${header}.${claim}`;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(serviceAccount.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned),
  ));
  const assertion = `${unsigned}.${base64url(signature)}`;
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const payload = await response.json();
  if (!response.ok || !payload.access_token) throw new Error("Google service authentication failed");
  return payload.access_token;
}

function firestoreValue(value: any): any {
  if (value === null) return { nullValue: null };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") return Number.isInteger(value)
    ? { integerValue: String(value) } : { doubleValue: value };
  if (typeof value === "string") return { stringValue: value };
  if (Array.isArray(value)) return { arrayValue: { values: value.map(firestoreValue) } };
  if (typeof value === "object") {
    const fields: Record<string, any> = {};
    for (const [key, item] of Object.entries(value)) fields[key] = firestoreValue(item);
    return { mapValue: { fields } };
  }
  return { nullValue: null };
}

function fromFirestoreValue(value: any): any {
  if (!value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return value.doubleValue;
  if ("timestampValue" in value) return value.timestampValue;
  if ("nullValue" in value) return null;
  if ("arrayValue" in value) return (value.arrayValue.values || []).map(fromFirestoreValue);
  if ("mapValue" in value) {
    const out: Record<string, any> = {};
    for (const [key, item] of Object.entries(value.mapValue.fields || {})) out[key] = fromFirestoreValue(item);
    return out;
  }
  return null;
}

function decodeDocument(doc: any): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [key, value] of Object.entries(doc.fields || {})) out[key] = fromFirestoreValue(value);
  return out;
}

function validateSchedule(schedule: any): boolean {
  if (!schedule || !schedule.isScheduled) return true;
  try {
    // The original Viewer uses the browser's local timezone. Its users are in Indonesia;
    // the server uses Asia/Jakarta to preserve the current production schedule semantics.
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: "Asia/Jakarta", weekday: "short", year: "numeric",
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
      hourCycle: "h23",
    }).formatToParts(new Date());
    const get = (type: string) => parts.find((part) => part.type === type)?.value || "";
    const dayMap: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    const currentDay = dayMap[get("weekday")];
    const currentTimeInt = Number(get("hour")) * 60 + Number(get("minute"));
    const today = `${get("year")}-${get("month")}-${get("day")}`;
    const [startH, startM] = schedule.start.time.split(":").map(Number);
    const [endH, endM] = schedule.end.time.split(":").map(Number);
    const startTimeInt = startH * 60 + startM;
    const endTimeInt = endH * 60 + endM;

    const isDayValid = (type: string, days: number[] = [], checkDay: number, createdAt: any) => {
      if (type === "tiap_hari") return true;
      if (type === "senin_jumat") return checkDay >= 1 && checkDay <= 5;
      if (type === "khusus") return Array.isArray(days) && days.includes(checkDay);
      if (type === "sekali") {
        const created = new Date(createdAt);
        const createdParts = new Intl.DateTimeFormat("en-CA", {
          timeZone: "Asia/Jakarta", year: "numeric", month: "2-digit", day: "2-digit",
        }).format(created);
        return createdParts === today;
      }
      return false;
    };

    const startToday = isDayValid(schedule.start.type, schedule.start.days, currentDay, schedule.createdAt);
    if (startTimeInt <= endTimeInt) {
      const endToday = isDayValid(schedule.end.type, schedule.end.days, currentDay, schedule.createdAt);
      return (startToday || endToday) && currentTimeInt >= startTimeInt && currentTimeInt <= endTimeInt;
    }
    const yesterday = currentDay === 0 ? 6 : currentDay - 1;
    return (startToday && currentTimeInt >= startTimeInt) ||
      (isDayValid(schedule.start.type, schedule.start.days, yesterday, schedule.createdAt) && currentTimeInt <= endTimeInt);
  } catch {
    return false;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, message: "Method not allowed" }, 405);

  try {
    const { token, deviceId } = await req.json();
    if (typeof token !== "string" || !token.trim() ||
        typeof deviceId !== "string" || !/^[A-Za-z0-9_-]{3,80}$/.test(deviceId)) {
      return json({ success: false, message: "Token dan identitas perangkat wajib diisi." }, 400);
    }

    const projectId = Deno.env.get("FIREBASE_PROJECT_ID") || "summarypengiriman";
    const serviceAccountRaw = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON");
    if (!serviceAccountRaw) return json({ success: false, message: "Konfigurasi Firebase server belum tersedia." }, 500);
    const serviceAccount = JSON.parse(serviceAccountRaw);
    if (serviceAccount.project_id !== projectId) {
      return json({ success: false, message: "Project Firebase tidak sesuai." }, 500);
    }

    const googleToken = await getGoogleAccessToken(serviceAccount);
    const queryResponse = await fetch(
      `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${googleToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          structuredQuery: {
            from: [{ collectionId: "access_tokens" }],
            where: { compositeFilter: { op: "AND", filters: [
              { fieldFilter: { field: { fieldPath: "token" }, op: "EQUAL", value: { stringValue: token.trim().toUpperCase() } } },
              { fieldFilter: { field: { fieldPath: "active" }, op: "EQUAL", value: { booleanValue: true } } },
            ] } },
            limit: 1,
          },
        }),
      },
    );
    const queryRows = await queryResponse.json();
    if (!queryResponse.ok) return json({ success: false, message: "Gagal memeriksa token Viewer." }, 503);
    const found = Array.isArray(queryRows) ? queryRows.find((row: any) => row.document) : null;
    if (!found) return json({ success: false, message: "AKSES DITOLAK: Token tidak terdaftar atau telah dinonaktifkan." }, 401);

    const document = found.document;
    const tokenData = decodeDocument(document);
    if (!validateSchedule(tokenData.schedule)) {
      return json({ success: false, message: "AKSES DITOLAK: Saat ini berada di luar jadwal aktif token." }, 403);
    }

    const registeredDevices: string[] = Array.isArray(tokenData.registeredDevices) ? tokenData.registeredDevices : [];
    const maxDevices = Number(tokenData.maxDevices) || 1;
    if (!registeredDevices.includes(deviceId)) {
      if (registeredDevices.length >= maxDevices) {
        return json({ success: false, message: `AKSES DITOLAK: Token penuh (${maxDevices} perangkat).` }, 403);
      }
      const docPath = document.name;
      const updateResponse = await fetch(
        `https://firestore.googleapis.com/v1/${docPath}:commit`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${googleToken}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            writes: [{
              transform: {
                document: docPath,
                fieldTransforms: [{
                  fieldPath: "registeredDevices",
                  appendMissingElements: { values: [{ stringValue: deviceId }] },
                }],
              },
            }],
          }),
        },
      );
      if (!updateResponse.ok) {
        return json({ success: false, message: "Gagal mendaftarkan perangkat ke token." }, 503);
      }
    }

    return json({
      success: true,
      tokenValid: true,
      deviceRegistered: true,
      message: "Otorisasi berhasil.",
    });
  } catch (error) {
    console.error("viewer-token-validation", error);
    return json({ success: false, message: "Kesalahan koneksi sistem." }, 503);
  }
});
