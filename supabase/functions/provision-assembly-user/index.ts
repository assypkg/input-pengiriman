// Secure account provisioning for Assembly.
// First account bootstrap requires ASSEMBLY_BOOTSTRAP_SECRET.
// After the first superuser exists, only an active superuser can add accounts.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://assypkg.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-bootstrap-secret",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const bootstrapSecret = Deno.env.get("ASSEMBLY_BOOTSTRAP_SECRET");
  if (!url || !anonKey || !serviceKey || !bootstrapSecret) {
    return json({ error: "Konfigurasi server belum lengkap." }, 500);
  }

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  try {
    const { username, password, full_name, role } = await req.json();
    const normalized = typeof username === "string" ? username.trim().toLowerCase() : "";
    if (!/^[a-z0-9._-]{3,32}$/.test(normalized) ||
        typeof password !== "string" || password.length < 8 ||
        typeof full_name !== "string" || !full_name.trim() ||
        !["superuser", "admin"].includes(role)) {
      return json({ error: "Data akun tidak valid. Password minimal 8 karakter." }, 400);
    }

    const { data: existingSuperusers, error: countError } = await admin
      .from("assembly_users").select("user_id").eq("role", "superuser").limit(1);
    if (countError) return json({ error: "Gagal memeriksa akun superuser." }, 500);

    if (!existingSuperusers?.length) {
      const supplied = req.headers.get("x-bootstrap-secret") || "";
      if (supplied !== bootstrapSecret || role !== "superuser" || normalized !== "angger") {
        return json({ error: "Bootstrap superuser tidak diizinkan." }, 403);
      }
    } else {
      const bearer = req.headers.get("Authorization") || "";
      const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : "";
      if (!token) return json({ error: "Login superuser diperlukan." }, 401);

      const caller = createClient(url, anonKey, {
        global: { headers: { Authorization: `Bearer ${token}` } },
        auth: { autoRefreshToken: false, persistSession: false },
      });
      const { data: userData, error: userError } = await caller.auth.getUser();
      if (userError || !userData.user) return json({ error: "Sesi tidak valid." }, 401);

      const { data: profile, error: profileError } = await admin
        .from("assembly_users")
        .select("role,is_active")
        .eq("user_id", userData.user.id)
        .maybeSingle();
      if (profileError || profile?.role !== "superuser" || profile.is_active !== true) {
        return json({ error: "Hanya superuser aktif yang dapat membuat akun." }, 403);
      }
    }

    const projectHost = new URL(url).hostname;
    const emailAlias = `${normalized}@${projectHost}`;
    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email: emailAlias,
      password,
      email_confirm: true,
      user_metadata: { username: normalized, full_name: full_name.trim() },
      app_metadata: { assembly_role: role },
    });
    if (createError || !created.user) {
      return json({ error: createError?.message || "Gagal membuat akun autentikasi." }, 400);
    }

    const { error: insertError } = await admin.from("assembly_users").insert({
      user_id: created.user.id,
      username: normalized,
      full_name: full_name.trim(),
      role,
      is_active: true,
    });
    if (insertError) {
      await admin.auth.admin.deleteUser(created.user.id);
      return json({ error: "Pembuatan profil gagal; akun autentikasi dibatalkan." }, 500);
    }

    return json({
      success: true,
      user: { username: normalized, full_name: full_name.trim(), role },
    }, 201);
  } catch (_error) {
    return json({ error: "Permintaan pembuatan akun tidak dapat diproses." }, 400);
  }
});
