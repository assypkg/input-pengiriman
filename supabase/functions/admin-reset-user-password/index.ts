// Superuser-only password reset for Assembly Admin Input accounts.
// A fresh temporary password is generated on the server and returned once to the caller.
const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

const RESETTABLE_USERS: Record<string, string> = {
  bayua: "Bayu A.",
  cyntiar: "Cyntia R.",
  nuruls: "Nurul S.",
};
const PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";

function generateTemporaryPassword(length = 20): string {
  const output: string[] = [];
  const limit = Math.floor(256 / PASSWORD_ALPHABET.length) * PASSWORD_ALPHABET.length;
  while (output.length < length) {
    const bytes = new Uint8Array(Math.max(16, length - output.length + 8));
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte >= limit) continue;
      output.push(PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.length]);
      if (output.length === length) break;
    }
  }
  return output.join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceKey) {
      return json({ success: false, error: "Konfigurasi autentikasi server belum lengkap." }, 500);
    }

    const bearer = req.headers.get("Authorization") || "";
    const accessToken = bearer.startsWith("Bearer ") ? bearer.slice(7) : "";
    if (!accessToken) return json({ success: false, error: "Sesi login diperlukan." }, 401);

    const authResponse = await fetch(supabaseUrl + "/auth/v1/user", {
      headers: { apikey: anonKey, Authorization: "Bearer " + accessToken },
    });
    if (!authResponse.ok) {
      return json({ success: false, error: "Sesi login tidak valid atau sudah berakhir." }, 401);
    }
    const authUser = await authResponse.json();
    if (!authUser?.id) return json({ success: false, error: "Identitas pengguna tidak dapat diverifikasi." }, 401);

    const callerProfileUrl = new URL(supabaseUrl + "/rest/v1/assembly_users");
    callerProfileUrl.searchParams.set("user_id", "eq." + authUser.id);
    callerProfileUrl.searchParams.set("select", "username,role,is_active");
    const callerResponse = await fetch(callerProfileUrl, {
      headers: { apikey: serviceKey, Authorization: "Bearer " + serviceKey },
    });
    if (!callerResponse.ok) return json({ success: false, error: "Profil pemohon gagal diverifikasi." }, 503);
    const callerRows = await callerResponse.json();
    const caller = callerRows?.[0];
    if (!caller || caller.is_active !== true || caller.role !== "superuser" || caller.username !== "angger") {
      return json({ success: false, error: "Hanya akun angger dengan role superuser yang boleh mengatur ulang password." }, 403);
    }

    const input = await req.json();
    const username = typeof input?.username === "string" ? input.username.trim().toLowerCase() : "";
    if (!Object.prototype.hasOwnProperty.call(RESETTABLE_USERS, username)) {
      return json({ success: false, error: "Akun target tidak termasuk daftar Admin yang boleh di-reset." }, 400);
    }

    const targetUrl = new URL(supabaseUrl + "/rest/v1/assembly_users");
    targetUrl.searchParams.set("username", "eq." + username);
    targetUrl.searchParams.set("select", "user_id,username,full_name,role,is_active");
    const targetResponse = await fetch(targetUrl, {
      headers: { apikey: serviceKey, Authorization: "Bearer " + serviceKey },
    });
    if (!targetResponse.ok) return json({ success: false, error: "Profil akun target gagal dibaca." }, 503);
    const targetRows = await targetResponse.json();
    const target = targetRows?.[0];
    if (!target || target.is_active !== true || target.role !== "admin" || !target.user_id) {
      return json({ success: false, error: "Akun target tidak aktif atau bukan akun Admin." }, 409);
    }

    const temporaryPassword = generateTemporaryPassword();
    const updateResponse = await fetch(
      supabaseUrl + "/auth/v1/admin/users/" + encodeURIComponent(target.user_id),
      {
        method: "PUT",
        headers: {
          apikey: serviceKey,
          Authorization: "Bearer " + serviceKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password: temporaryPassword }),
      },
    );
    if (!updateResponse.ok) {
      const details = await updateResponse.text();
      console.error("admin-reset-user-password update failed:", updateResponse.status, details.slice(0, 500));
      return json({ success: false, error: "Supabase gagal memperbarui password akun target." }, 503);
    }

    console.log("Assembly admin password reset", {
      by: caller.username,
      target: username,
      at: new Date().toISOString(),
    });

    return json({
      success: true,
      username,
      full_name: target.full_name || RESETTABLE_USERS[username],
      temporary_password: temporaryPassword,
      message: "Password berhasil di-reset. Password hanya ditampilkan pada hasil ini.",
    });
  } catch (error) {
    console.error("admin-reset-user-password", error);
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Permintaan reset password gagal diproses.",
    }, 500);
  }
});
