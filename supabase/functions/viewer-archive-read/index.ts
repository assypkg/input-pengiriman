// Read-only archive access for View Summary users.
// The private bucket is never exposed directly to browsers.
// Every request first passes the existing Firebase Viewer-token rules.
const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const { token, deviceId, archivePath } = await req.json();
    if (typeof token !== "string" || typeof deviceId !== "string" ||
        typeof archivePath !== "string" ||
        !/^[A-Za-z0-9_-]{3,80}$/.test(deviceId) ||
        archivePath.length > 240 ||
        !/^[A-Za-z0-9][A-Za-z0-9_./-]*\.json$/.test(archivePath) ||
        archivePath.split("/").some((part: string) => !part || part === "." || part === "..")) {
      return json({ error: "Parameter permintaan arsip tidak valid." }, 400);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceKey) return json({ error: "Konfigurasi server belum lengkap." }, 500);

    const validation = await fetch(`${supabaseUrl}/functions/v1/validate-viewer-token`, {
      method: "POST",
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token, deviceId }),
    });
    const validationBody = await validation.json();
    if (!validation.ok || validationBody.success !== true) {
      return json({
        success: false,
        error: validationBody.message || "Akses arsip ditolak.",
      }, validation.status || 403);
    }

    const encodedPath = archivePath.split("/").map(encodeURIComponent).join("/");
    const archiveResponse = await fetch(
      `${supabaseUrl}/storage/v1/object/arsip-pengiriman/${encodedPath}`,
      { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } },
    );
    if (archiveResponse.status === 404) {
      return json({ success: false, error: "Arsip tidak ditemukan." }, 404);
    }
    if (!archiveResponse.ok) {
      return json({ success: false, error: "Arsip gagal dibaca dari penyimpanan." }, 503);
    }

    const archive = await archiveResponse.json();
    return json({ success: true, archive });
  } catch (error) {
    console.error("viewer-archive-read", error);
    return json({ success: false, error: "Permintaan arsip tidak dapat diproses." }, 503);
  }
});
