// Exchange a verified Supabase Assembly session for a Firebase custom token.
// Firebase service-account credentials remain server-side in Edge Function Secrets.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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

async function createFirebaseCustomToken(serviceAccount: any, uid: string, claims: Record<string, unknown>) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 3600,
    uid,
    ...claims,
  }));
  const unsigned = `${header}.${payload}`;
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
  return `${unsigned}.${base64url(signature)}`;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const projectId = Deno.env.get("FIREBASE_PROJECT_ID") || "summarypengiriman";
    const serviceAccountRaw = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_JSON");
    const bearer = req.headers.get("Authorization") || "";
    const accessToken = bearer.startsWith("Bearer ") ? bearer.slice(7) : "";

    if (!url || !anonKey || !serviceKey || !serviceAccountRaw) {
      return json({ error: "Konfigurasi autentikasi server belum lengkap." }, 500);
    }
    if (!accessToken) return json({ error: "Sesi login diperlukan." }, 401);

    const caller = createClient(url, anonKey, {
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: authData, error: authError } = await caller.auth.getUser();
    if (authError || !authData.user) return json({ error: "Sesi Supabase tidak valid." }, 401);

    const admin = createClient(url, serviceKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: profile, error: profileError } = await admin
      .from("assembly_users")
      .select("username,full_name,role,is_active")
      .eq("user_id", authData.user.id)
      .maybeSingle();

    if (profileError) return json({ error: "Gagal memeriksa profil Assembly." }, 503);
    if (!profile || profile.is_active !== true || !["superuser", "admin"].includes(profile.role)) {
      return json({ error: "Akun tidak aktif atau tidak memiliki akses Assembly." }, 403);
    }

    const serviceAccount = JSON.parse(serviceAccountRaw);
    if (serviceAccount.project_id !== projectId || !serviceAccount.client_email || !serviceAccount.private_key) {
      return json({ error: "Konfigurasi Firebase service account tidak sesuai." }, 500);
    }

    const firebaseToken = await createFirebaseCustomToken(
      serviceAccount,
      `assembly_${authData.user.id}`,
      {
        assemblyRole: profile.role,
        assemblyUsername: profile.username,
        assemblyUserId: authData.user.id,
      },
    );

    return json({
      firebase_custom_token: firebaseToken,
      firebase_project_id: projectId,
      profile: {
        username: profile.username,
        full_name: profile.full_name,
        role: profile.role,
      },
    });
  } catch (error) {
    console.error("firebase-custom-token", error);
    return json({ error: "Gagal membuat sesi Firebase." }, 500);
  }
});
