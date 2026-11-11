# Supabase Authentication Foundation — Assembly

This branch contains the initial username/password authentication backend for the Assembly shipment apps. It does not change either live GitHub Pages app.

## Files
- `supabase/migrations/202611120001_assembly_users.sql`: user profile table and row-level security.
- `supabase/functions/username-login/index.ts`: username/password login endpoint.
- `supabase/functions/provision-assembly-user/index.ts`: secure account provisioning endpoint.

## Important security model
- Users enter a username and password; no personal email address is required.
- Supabase Auth uses a deterministic internal email alias: `<username>@<Supabase project hostname>`.
- Email confirmation is set to true at account creation, and the project must have email confirmation disabled as configured in the dashboard.
- The service-role key is used only inside Edge Functions and must never be added to browser code or committed to GitHub.
- The first account can only be bootstrapped as username `angger`, role `superuser`, using the server-side `ASSEMBLY_BOOTSTRAP_SECRET`.
- After the first superuser exists, only an authenticated, active superuser can provision additional accounts.
- This is backend groundwork only. The existing Firebase login screens are not changed in this branch.

## Deployment sequence
1. Apply the SQL migration in Supabase SQL Editor.
2. Deploy both Edge Functions.
3. Set Edge Function secret `ASSEMBLY_BOOTSTRAP_SECRET` to a long random value. Do not send it in chat or commit it.
4. Invoke `provision-assembly-user` once with the bootstrap header and the initial Angger account details.
5. Sign in through `username-login` and then provision the remaining admin accounts while authenticated as Angger.
6. Only after backend tests pass, integrate the login flow into both apps.

## Function endpoints
- `POST /functions/v1/username-login`: JSON body `{"username":"angger","password":"..."}`.
- `POST /functions/v1/provision-assembly-user`: JSON body `{"username":"...","password":"...","full_name":"...","role":"admin"}`.

Bootstrap request also requires header `x-bootstrap-secret`. Subsequent provisioning requests require `Authorization: Bearer <superuser access token>`.

Do not enable anonymous access to Storage. Storage policies will be configured separately after authentication is verified.
