-- Assembly username authentication foundation
-- Apply once to the Supabase project before deploying the Edge Functions.

create table if not exists public.assembly_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  full_name text not null,
  role text not null check (role in ('superuser', 'admin')),
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create unique index if not exists assembly_users_username_lower_uidx
  on public.assembly_users (lower(username));

alter table public.assembly_users enable row level security;

revoke all on table public.assembly_users from anon, authenticated;
grant select on table public.assembly_users to authenticated;

drop policy if exists "Users can read own Assembly profile" on public.assembly_users;
create policy "Users can read own Assembly profile"
  on public.assembly_users
  for select
  to authenticated
  using (auth.uid() = user_id);
