# Supabase Authentication Foundation — Assembly

This branch contains the initial username/password authentication backend for the Assembly Admin/Input workflow. It does not change either live GitHub Pages app.

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
- The View Summary Pengiriman app remains on its existing corporate token flow for Kabag and employees. Do not replace it with Supabase username/password.
- Supabase username/password is reserved for internal Admin/Input users and protected archive administration.
- The current Viewer token validation and Firestore session behavior must remain unchanged during the Admin authentication rollout.
- This is backend groundwork only. The existing Firebase login screens are not changed in this branch.

## Deployment sequence
1. Apply the SQL migration in Supabase SQL Editor.
2. Deploy both Edge Functions.
3. Set Edge Function secret `ASSEMBLY_BOOTSTRAP_SECRET` to a long random value. Do not send it in chat or commit it.
4. Invoke `provision-assembly-user` once with the bootstrap header and the initial Angger account details.
5. Sign in through `username-login` and then provision the remaining admin accounts while authenticated as Angger.
6. Only after backend tests pass, integrate Supabase login into the Admin/Input app only. Keep the View Summary app's existing token login unchanged.

## Function endpoints
- `POST /functions/v1/username-login`: JSON body `{"username":"angger","password":"..."}`.
- `POST /functions/v1/provision-assembly-user`: JSON body `{"username":"...","password":"...","full_name":"...","role":"admin"}`.

Bootstrap request also requires header `x-bootstrap-secret`. Subsequent provisioning requests require `Authorization: Bearer <superuser access token>`.

Do not enable anonymous access to Storage. Storage policies will be configured separately after authentication is verified.

## Access separation decision

| Application / user group | Authentication |
| --- | --- |
| View Summary — Kabag and employees | Existing corporate access token; unchanged |
| Admin/Input — Angger, Bayu A, Cyntia R, Nurul S | Supabase username/password |
| Archive administration | Supabase authenticated role; superuser-only permanent deletion |
| Archive viewing from View Summary | Must be exposed through a separate read-only server endpoint that validates the existing Viewer token; never expose the private Storage bucket directly to anonymous clients |

The archive read endpoint is a later integration task. Before implementing it, inspect the existing Viewer token validation source and reproduce its validation rules server-side. Do not assume the localStorage token is a Firebase Auth JWT.
