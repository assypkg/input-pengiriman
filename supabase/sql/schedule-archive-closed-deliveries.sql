-- Run once in Supabase Dashboard > SQL Editor after setting the Edge Function secrets.
--
-- Required Edge Function secrets:
--   FIREBASE_SERVICE_ACCOUNT_JSON = the Firebase service-account JSON for project summarypengiriman
--                                  (grant the service account the Cloud Datastore User role)
--   ARCHIVE_CRON_SECRET           = a long random secret, at least 32 characters
--
-- IMPORTANT: use the exact same ARCHIVE_CRON_SECRET value in the Vault entry below.
-- Do not put the service-account JSON or cron secret in GitHub or in the application HTML.

create extension if not exists pg_cron with schema pg_catalog;
create extension if not exists pg_net with schema extensions;
create extension if not exists supabase_vault with schema vault;

-- Store the scheduler's request details in Vault rather than in the cron command.
-- Replace the placeholder with the same value configured as Edge Function secret ARCHIVE_CRON_SECRET.
select vault.create_secret(
  'https://wcsjjdzxnwhzqkqninky.supabase.co/functions/v1/archive-closed-deliveries',
  'archive_function_url',
  'Private endpoint used by the daily CLOSED delivery archive scheduler'
);

select vault.create_secret(
  'sb_publishable_UadEwYUBc9Whu3m7VKrF6g_lAjS_Y4U',
  'archive_function_apikey',
  'Publishable key used by the daily archive scheduler request'
);

select vault.create_secret(
  'REPLACE_WITH_THE_SAME_ARCHIVE_CRON_SECRET_CONFIGURED_IN_EDGE_FUNCTIONS',
  'archive_cron_secret',
  'Shared secret authorizing the private archive scheduler'
);

-- Remove an older job with the same name so this setup can be re-applied safely.
select cron.unschedule(jobid)
from cron.job
where jobname = 'daily-archive-closed-deliveries';

-- 17:15 UTC = 00:15 WIB (Asia/Jakarta) every day.
-- H+1 has ended by this time; a delivery dated H becomes eligible on H+2.
select cron.schedule(
  'daily-archive-closed-deliveries',
  '15 17 * * *',
  $job$
    select net.http_post(
      url := (
        select decrypted_secret
        from vault.decrypted_secrets
        where name = 'archive_function_url'
      ),
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'apikey', (
          select decrypted_secret
          from vault.decrypted_secrets
          where name = 'archive_function_apikey'
        ),
        'x-archive-cron-secret', (
          select decrypted_secret
          from vault.decrypted_secrets
          where name = 'archive_cron_secret'
        )
      ),
      body := jsonb_build_object('action', 'scheduled-archive')
    );
  $job$
);

-- Verify that the daily job is active.
select jobid, jobname, schedule, active
from cron.job
where jobname = 'daily-archive-closed-deliveries';
