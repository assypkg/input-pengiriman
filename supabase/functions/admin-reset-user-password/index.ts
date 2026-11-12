// Superuser-only reset/provisioning for Assembly Admin accounts.
// Existing Admin profiles are reset in place. Missing profiles are provisioned safely
// only when the auth identity matches the reserved username alias.
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
    if (!authResponse.ok) return json({ success: false, error: "Sesi login tidak valid atau sudah berakhir." }, 401);
    const authUser = await authResponse.json();
    if (!authUser?.id) return json({ success: false, error: "Identitas pengguna tidak dapat diverifikasi." }, 401);

    const callerUrl = new URL(supabaseUrl + "/rest/v1/assembly_users");
    callerUrl.searchParams.set("user_id", "eq." + authUser.id);
    callerUrl.searchParams.set("select", "username,role,is_active");
    const callerResponse = await fetch(callerUrl, {
      headers: { apikey: serviceKey, Authorization: "Bearer " + serviceKey },
    });
    if (!callerResponse.ok) return json({ success: false, error: "Profil pemohon gagal diverifikasi." }, 503);
    const callerRows = await callerResponse.json();
    const caller = callerRows?.[0];
    if (!caller || caller.is_active !== true || caller.role !== "superuser" || caller.username !== "angger") {
      return json({ success: false, error: "Hanya akun angger dengan role superuser aktif yang boleh mengatur ulang password." }, 403);
    }

    const input = await req.json();
    const username = typeof input?.username === "string" ? input.username.trim().toLowerCase() : "";
    const password = typeof input?.password === "string" ? input.password : "";
    const fullName = RESETTABLE_USERS[username];
    if (!fullName) return json({ success: false, error: "Akun target tidak termasuk daftar Admin yang boleh di-reset." }, 400);
    if (password.length < 8 || password.length > 72) return json({ success: false, error: "Password harus 8–72 karakter." }, 400);

    const targetUrl = new URL(supabaseUrl + "/rest/v1/assembly_users");
    targetUrl.searchParams.set("username", "eq." + username);
    targetUrl.searchParams.set("select", "user_id,username,full_name,role,is_active");
    const targetResponse = await fetch(targetUrl, {
      headers: { apikey: serviceKey, Authorization: "Bearer " + serviceKey },
    });
    if (!targetResponse.ok) return json({ success: false, error: "Profil akun target gagal dibaca." }, 503);
    const targetRows = await targetResponse.json();
    let target = targetRows?.[0];

    const projectHost = new URL(supabaseUrl).hostname;
    const emailAlias = username + "@" + projectHost;
    const newPassword = password;

    if (!target) {
      // Recover only a matching reserved alias; never adopt an unrelated Auth user.
      const adminHeaders = { apikey: serviceKey, Authorization: "Bearer " + serviceKey, "Content-Type": "application/json" };
      const lookupResponse = await fetch(supabaseUrl + "/auth/v1/admin/users?page=1&per_page=1000", {
        headers: adminHeaders,
      });
      if (!lookupResponse.ok) return json({ success: false, error: "Daftar akun autentikasi gagal diperiksa." }, 503);
      const lookupPayload = await lookupResponse.json();
      const users = Array.isArray(lookupPayload?.users) ? lookupPayload.users : [];
      let authTarget = users.find((u: any) => (u.email || "").toLowerCase() === emailAlias.toLowerCase());

      if (authTarget && authTarget.user_metadata?.username !== username) {
        return json({ success: false, error: "Alias akun target sudah digunakan identitas lain. Perlu pemeriksaan manual." }, 409);
      }
      if (!authTarget) {
        const createResponse = await fetch(supabaseUrl + "/auth/v1/admin/users", {
          method: "POST",
          headers: adminHeaders,
          body: JSON.stringify({
            email: emailAlias,
            password: newPassword,
            email_confirm: true,
            user_metadata: { username, full_name: fullName },
            app_metadata: { assembly_role: "admin" },
          }),
        });
        const createdPayload = await createResponse.json().catch(() => ({}));
        if (!createResponse.ok || !createdPayload?.id) {
          console.error("admin reset provision failed", createResponse.status, JSON.stringify(createdPayload).slice(0, 500));
          return json({ success: false, error: "Akun Admin belum dapat dibuat di Supabase." }, 503);
        }
        authTarget = createdPayload;
      } else {
        const updateAuth = await fetch(supabaseUrl + "/auth/v1/admin/users/" + encodeURIComponent(authTarget.id), {
          method: "PUT",
          headers: adminHeaders,
          body: JSON.stringify({ password: newPassword }),
        });
        if (!updateAuth.ok) return json({ success: false, error: "Password akun autentikasi gagal diperbarui." }, 503);
      }

      const profileInsert = await fetch(supabaseUrl + "/rest/v1/assembly_users", {
        method: "POST",
        headers: {
          apikey: serviceKey,
          Authorization: "Bearer " + serviceKey,
          "Content-Type": "application/json",
          Prefer: "return=representation",
        },
        body: JSON.stringify({
          user_id: authTarget.id,
          username,
          full_name: fullName,
          role: "admin",
          is_active: true,
        }),
      });
      const inserted = await profileInsert.json().catch(() => []);
      if (!profileInsert.ok) {
        console.error("admin profile provision failed", profileInsert.status, JSON.stringify(inserted).slice(0, 500));
        return json({ success: false, error: "Akun autentikasi tersedia, tetapi profil Admin gagal dibuat. Hubungi Superuser." }, 503);
      }
      target = inserted?.[0] || { username, full_name: fullName, role: "admin", is_active: true };
      // New Auth user received the supplied password; existing one was updated.
      return json({ success: true, username, full_name: fullName, password_updated: true,
        message: "Akun Admin berhasil disiapkan dan password diperbarui." });
    }

    if (target.is_active !== true || target.role !== "admin" || !target.user_id) {
      return json({ success: false, error: "Akun target tidak aktif atau bukan akun Admin. Tidak ada perubahan yang dilakukan." }, 409);
    }

    const updateResponse = await fetch(
      supabaseUrl + "/auth/v1/admin/users/" + encodeURIComponent(target.user_id),
      {
        method: "PUT",
        headers: {
          apikey: serviceKey,
          Authorization: "Bearer " + serviceKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password: newPassword }),
      },
    );
    if (!updateResponse.ok) {
      const details = await updateResponse.text();
      console.error("admin reset password update failed:", updateResponse.status, details.slice(0, 500));
      return json({ success: false, error: "Supabase gagal memperbarui password akun target." }, 503);
    }

    console.log("Assembly admin password reset", { by: caller.username, target: username, at: new Date().toISOString() });
    return json({
      success: true,
      username,
      full_name: target.full_name || fullName,
      password_updated: true,
      message: "Password berhasil diperbarui.",
    });
  } catch (error) {
    console.error("admin-reset-user-password", error);
    return json({ success: false, error: error instanceof Error ? error.message : "Permintaan reset password gagal diproses." }, 500);
  }
});
