// Username/password login for Assembly apps.
// The browser never receives the Supabase service-role key.
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
    const { username, password } = await req.json();
    if (typeof username !== "string" || typeof password !== "string") {
      return json({ error: "Username dan password wajib diisi." }, 400);
    }

    const normalized = username.trim().toLowerCase();
    if (!/^[a-z0-9._-]{3,32}$/.test(normalized) || password.length < 8) {
      return json({ error: "Format username atau password tidak valid." }, 400);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceKey) {
      return json({ error: "Konfigurasi autentikasi server belum lengkap." }, 500);
    }

    const projectHost = new URL(supabaseUrl).hostname;
    const emailAlias = `${normalized}@${projectHost}`;
    const authResponse = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { apikey: anonKey, "Content-Type": "application/json" },
      body: JSON.stringify({ email: emailAlias, password }),
    });

    const authPayload = await authResponse.json();
    if (!authResponse.ok || !authPayload.access_token || !authPayload.user?.id) {
      return json({ error: "Username atau password salah." }, 401);
    }

    const profileResponse = await fetch(
      `${supabaseUrl}/rest/v1/assembly_users?user_id=eq.${encodeURIComponent(authPayload.user.id)}&select=username,full_name,role,is_active`,
      { headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` } },
    );
    if (!profileResponse.ok) {
      return json({ error: "Profil pengguna gagal diverifikasi." }, 503);
    }

    const profiles = await profileResponse.json();
    const profile = profiles[0];
    if (!profile || profile.username !== normalized || profile.is_active !== true) {
      return json({ error: "Akun tidak aktif atau belum memiliki hak akses Assembly." }, 403);
    }

    return json({
      access_token: authPayload.access_token,
      refresh_token: authPayload.refresh_token,
      token_type: authPayload.token_type,
      expires_in: authPayload.expires_in,
      user: authPayload.user,
      profile: {
        username: profile.username,
        full_name: profile.full_name,
        role: profile.role,
      },
    });
  } catch (_error) {
    return json({ error: "Permintaan login tidak dapat diproses." }, 400);
  }
});
