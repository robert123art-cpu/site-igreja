-- Per-user SIGA module grants. This is intentionally separate from
-- siga_user_unit_permissions so existing unit assignments and finance.read/write
-- flags remain unchanged. There is no backfill: non-admin users start with no
-- module access until an administrator assigns it. Admin JWT roles remain full access.

create table public.siga_user_module_permissions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  modules jsonb not null default '{}'::jsonb,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now(),
  constraint siga_user_module_permissions_valid_modules
    check (
      jsonb_typeof(modules) = 'object'
      and modules <@ '{"members":true,"meetings":true,"finance":true,"bank_accounts":true,"assets":true,"agenda":true,"reports":true}'::jsonb
    )
);

alter table public.siga_user_module_permissions enable row level security;
revoke all on table public.siga_user_module_permissions from public, anon, authenticated;
grant select on table public.siga_user_module_permissions to authenticated;
grant all on table public.siga_user_module_permissions to service_role;

create policy siga_module_permissions_read_self_or_admin
on public.siga_user_module_permissions
for select
to authenticated
using (
  user_id = (select auth.uid())
  or coalesce(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin', false)
);

create or replace function public.siga_has_module_access(module_key text)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select case
    when module_key = any (array['members','meetings','finance','bank_accounts','assets','agenda','reports'])
    then
      coalesce(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin', false)
      or exists (
        select 1
        from public.siga_user_module_permissions p
        where p.user_id = (select auth.uid())
          and p.modules @> jsonb_build_object(module_key, true)
      )
    else false
  end;
$$;

revoke all on function public.siga_has_module_access(text) from public, anon;
grant execute on function public.siga_has_module_access(text) to authenticated;

-- Restrict direct member-directory reads, preserving the CCJ Digital user's
-- existing own-member-row exception and all existing admin write policies.
create policy siga_module_members_select
on public.members as restrictive
for select to authenticated
using (
  public.siga_has_module_access('members')
  or (
    ((select auth.jwt()) -> 'app_metadata' ->> 'app') = 'ccj_digital'
    and id::text = ((select auth.jwt()) -> 'app_metadata' ->> 'member_id')
  )
);

create policy siga_module_siga_members_select
on public.siga_members as restrictive
for select to authenticated
using (public.siga_has_module_access('members'));

-- Module access to the editable SIGA member table includes its current CRUD actions.
-- The legacy public.members table remains write-restricted to designated administrators
-- because it is also used by CCJ Digital and QR-account flows.
create policy siga_module_siga_members_insert
on public.siga_members
for insert to authenticated
with check (public.siga_has_module_access('members'));

create policy siga_module_siga_members_update
on public.siga_members
for update to authenticated
using (public.siga_has_module_access('members'))
with check (public.siga_has_module_access('members'));

create policy siga_module_siga_members_delete
on public.siga_members
for delete to authenticated
using (public.siga_has_module_access('members'));

-- Meeting grants permit the existing meeting and attendance data operations.
create policy siga_module_meetings_insert
on public.meetings
for insert to authenticated
with check (public.siga_has_module_access('meetings'));

create policy siga_module_meetings_update
on public.meetings
for update to authenticated
using (public.siga_has_module_access('meetings'))
with check (public.siga_has_module_access('meetings'));

create policy siga_module_meetings_delete
on public.meetings
for delete to authenticated
using (public.siga_has_module_access('meetings'));

create policy siga_module_attendance_insert
on public.attendance
for insert to authenticated
with check (public.siga_has_module_access('meetings'));

create policy siga_module_attendance_update
on public.attendance
for update to authenticated
using (public.siga_has_module_access('meetings'))
with check (public.siga_has_module_access('meetings'));

create policy siga_module_attendance_delete
on public.attendance
for delete to authenticated
using (public.siga_has_module_access('meetings'));

-- Agenda grants permit reading and managing the events table.
create policy siga_module_events_insert
on public.events
for insert to authenticated
with check (public.siga_has_module_access('agenda'));

create policy siga_module_events_update
on public.events
for update to authenticated
using (public.siga_has_module_access('agenda'))
with check (public.siga_has_module_access('agenda'));

create policy siga_module_events_delete
on public.events
for delete to authenticated
using (public.siga_has_module_access('agenda'));

-- Reports can read meeting data; all existing meeting write/admin policies remain.
create policy siga_module_meetings_select
on public.meetings as restrictive
for select to authenticated
using (
  public.siga_has_module_access('meetings')
  or public.siga_has_module_access('reports')
);

create policy siga_module_attendance_select
on public.attendance
for select to authenticated
using (
  public.siga_has_module_access('meetings')
  or public.siga_has_module_access('reports')
);

create policy siga_module_events_select
on public.events as restrictive
for select to authenticated
using (public.siga_has_module_access('agenda'));

-- Finance module access layers on top of the existing per-unit finance.read
-- and finance.write RLS policies; banking/report views remain unit-scoped.
create policy siga_module_chart_accounts_select
on public.siga_chart_of_accounts as restrictive
for select to authenticated
using (
  public.siga_has_module_access('finance')
  or public.siga_has_module_access('reports')
);

create policy siga_module_financial_accounts_select
on public.siga_financial_accounts as restrictive
for select to authenticated
using (
  public.siga_has_module_access('finance')
  or public.siga_has_module_access('bank_accounts')
  or public.siga_has_module_access('reports')
);

create policy siga_module_financial_accounts_insert
on public.siga_financial_accounts as restrictive
for insert to authenticated
with check (public.siga_has_module_access('bank_accounts'));

create policy siga_module_financial_accounts_update
on public.siga_financial_accounts as restrictive
for update to authenticated
using (public.siga_has_module_access('bank_accounts'))
with check (public.siga_has_module_access('bank_accounts'));

create policy siga_module_financial_accounts_delete
on public.siga_financial_accounts as restrictive
for delete to authenticated
using (public.siga_has_module_access('bank_accounts'));

create policy siga_module_financial_transactions_select
on public.siga_financial_transactions as restrictive
for select to authenticated
using (
  public.siga_has_module_access('finance')
  or public.siga_has_module_access('bank_accounts')
  or public.siga_has_module_access('reports')
);

create policy siga_module_financial_transactions_insert
on public.siga_financial_transactions as restrictive
for insert to authenticated
with check (public.siga_has_module_access('finance'));

create policy siga_module_financial_transactions_update
on public.siga_financial_transactions as restrictive
for update to authenticated
using (public.siga_has_module_access('finance'))
with check (public.siga_has_module_access('finance'));

create policy siga_module_financial_transactions_delete
on public.siga_financial_transactions as restrictive
for delete to authenticated
using (public.siga_has_module_access('finance'));
