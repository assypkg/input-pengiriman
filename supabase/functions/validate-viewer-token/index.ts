// Validate the existing corporate Viewer token through Firestore Security Rules.
// This endpoint uses the same public Firebase Web API key as the Viewer app.
// It does not bypass Firestore rules and does not use or expose a service-account key.
// The browser's existing login flow registers the device before archive access is requested.

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

const FIREBASE_PROJECT_ID = "summarypengiriman";
const FIREBASE_WEB_API_KEY = "AIzaSyCi7Tr4DDGvWg-a8Fd_tybUS7bBq0hrvaY";

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
    for (const [key, item] of Object.entries(value.mapValue.fields || {})) {
      out[key] = fromFirestoreValue(item);
    }
    return out;
  }
  return null;
}

function decodeDocument(doc: any): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [key, value] of Object.entries(doc.fields || {})) {
    out[key] = fromFirestoreValue(value);
  }
  return out;
}

function validateSchedule(schedule: any): boolean {
  if (!schedule || !schedule.isScheduled) return true;
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: "Asia/Jakarta",
      weekday: "short",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    }).formatToParts(new Date());
    const get = (type: string) => parts.find((part) => part.type === type)?.value || "";
    const dayMap: Record<string, number> = {
      Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6,
    };
    const currentDay = dayMap[get("weekday")];
    const currentTimeInt = Number(get("hour")) * 60 + Number(get("minute"));
    const today = get("year") + "-" + get("month") + "-" + get("day");
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
        const createdDay = new Intl.DateTimeFormat("en-CA", {
          timeZone: "Asia/Jakarta", year: "numeric", month: "2-digit", day: "2-digit",
        }).format(created);
        return createdDay === today;
      }
      return false;
    };

    const startToday = isDayValid(schedule.start.type, schedule.start.days, currentDay, schedule.createdAt);
    if (startTimeInt <= endTimeInt) {
      const endToday = isDayValid(schedule.end.type, schedule.end.days, currentDay, schedule.createdAt);
      return (startToday || endToday) &&
        currentTimeInt >= startTimeInt && currentTimeInt <= endTimeInt;
    }
    const yesterday = currentDay === 0 ? 6 : currentDay - 1;
    return (startToday && currentTimeInt >= startTimeInt) ||
      (isDayValid(schedule.start.type, schedule.start.days, yesterday, schedule.createdAt) &&
        currentTimeInt <= endTimeInt);
  } catch {
    return false;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, message: "Method not allowed." }, 405);

  try {
    const input = await req.json();
    const token = typeof input?.token === "string" ? input.token.trim().toUpperCase() : "";
    const deviceId = typeof input?.deviceId === "string" ? input.deviceId : "";
    if (!token || token.length > 120 || !/^[A-Za-z0-9_-]{3,80}$/.test(deviceId)) {
      return json({ success: false, message: "Token atau identitas perangkat tidak valid." }, 400);
    }

    const queryUrl = new URL(
      "https://firestore.googleapis.com/v1/projects/" +
      FIREBASE_PROJECT_ID +
      "/databases/(default)/documents:runQuery",
    );
    queryUrl.searchParams.set("key", FIREBASE_WEB_API_KEY);
    const queryResponse = await fetch(queryUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: "access_tokens" }],
          where: {
            compositeFilter: {
              op: "AND",
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: "token" },
                    op: "EQUAL",
                    value: { stringValue: token },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: "active" },
                    op: "EQUAL",
                    value: { booleanValue: true },
                  },
                },
              ],
            },
          },
          limit: 1,
        },
      }),
    });

    if (!queryResponse.ok) {
      console.error("viewer-token-firestore-query", queryResponse.status);
      return json({ success: false, message: "Firestore menolak pemeriksaan token Viewer." }, 503);
    }

    const queryRows = await queryResponse.json();
    const found = Array.isArray(queryRows) ? queryRows.find((row: any) => row.document) : null;
    if (!found) {
      return json({
        success: false,
        message: "AKSES DITOLAK: Token tidak terdaftar atau telah dinonaktifkan.",
      }, 401);
    }

    const tokenData = decodeDocument(found.document);
    if (!validateSchedule(tokenData.schedule)) {
      return json({
        success: false,
        message: "AKSES DITOLAK: Saat ini berada di luar jadwal aktif token.",
      }, 403);
    }

    const registeredDevices = Array.isArray(tokenData.registeredDevices)
      ? tokenData.registeredDevices
      : [];
    if (!registeredDevices.includes(deviceId)) {
      return json({
        success: false,
        message: "AKSES DITOLAK: Perangkat belum terdaftar pada token ini. Login Viewer kembali.",
      }, 403);
    }

    return json({
      success: true,
      tokenValid: true,
      deviceRegistered: true,
      message: "Otorisasi Viewer berhasil.",
    });
  } catch (error) {
    console.error("viewer-token-validation", error);
    return json({ success: false, message: "Validasi token Viewer gagal diproses." }, 503);
  }
});
