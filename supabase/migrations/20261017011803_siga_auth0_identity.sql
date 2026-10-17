-- SIGA uses Auth0 subjects for login while keeping UUIDs for unit assignments and audit history.
-- Apply only after configuring Supabase Third-Party Auth for the matching Auth0 issuer.


create schema if not exists siga_private;
revoke all on schema siga_private from public, anon;
grant usage on schema siga_private to authenticated;

create table if not exists public.siga_user_identities (
  id uuid primary key default gen_random_uuid(),
  auth0_sub text,
  email text,
  email_key text,
  full_name text not null default '',
  role text not null default 'user' check (role in ('admin', 'user')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint siga_user_identities_auth0_sub_unique unique (auth0_sub)
);

comment on table public.siga_user_identities is
  'Private mapping from Auth0 subjects to stable SIGA UUIDs used by unit assignments.';
create unique index if not exists siga_user_identities_email_key_uidx
  on public.siga_user_identities (email_key)
  where email_key is not null;

alter table public.siga_user_identities enable row level security;
revoke all on table public.siga_user_identities from public, anon, authenticated;
grant select, insert, update, delete on table public.siga_user_identities to service_role;

-- Keep UUIDs already referenced by unit permissions and audit fields.
insert into public.siga_user_identities (id, auth0_sub, email, email_key, full_name, role)
select
  u.id,
  null,
  u.email,
  case when u.email is null then null else lower(btrim(u.email)) end,
  coalesce(nullif(u.raw_user_meta_data ->> 'full_name', ''), nullif(u.raw_user_meta_data ->> 'name', ''), ''),
  case when u.raw_app_meta_data ->> 'role' = 'admin' then 'admin' else 'user' end
from auth.users as u
on conflict (id) do nothing;

alter table public.siga_units
  alter column created_by drop default,
  alter column updated_by drop default;

alter table public.siga_user_unit_permissions
  alter column granted_by drop default;

alter table public.siga_units
  drop constraint if exists siga_units_created_by_fkey,
  drop constraint if exists siga_units_updated_by_fkey,
  add constraint siga_units_created_by_fkey
    foreign key (created_by) references public.siga_user_identities(id) on delete set null,
  add constraint siga_units_updated_by_fkey
    foreign key (updated_by) references public.siga_user_identities(id) on delete set null;

alter table public.siga_user_unit_permissions
  drop constraint if exists siga_user_unit_permissions_granted_by_fkey,
  drop constraint if exists siga_user_unit_permissions_user_id_fkey,
  add constraint siga_user_unit_permissions_granted_by_fkey
    foreign key (granted_by) references public.siga_user_identities(id) on delete set null,
  add constraint siga_user_unit_permissions_user_id_fkey
    foreign key (user_id) references public.siga_user_identities(id) on delete cascade;

create or replace function siga_private.current_user_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select identity.id
  from public.siga_user_identities as identity
  where identity.auth0_sub = (select auth.jwt() ->> 'sub')
    and (select auth.jwt() ->> 'iss') = 'https://dev-bggmfdxl7xrd7z2c.us.auth0.com/'
    and (select auth.jwt() ->> 'role') = 'authenticated'
  limit 1;
$$;

create or replace function siga_private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.siga_user_identities as identity
    where identity.id = (select siga_private.current_user_id())
      and identity.role = 'admin'
  );
$$;

revoke all on function siga_private.current_user_id() from public, anon;
revoke all on function siga_private.is_admin() from public, anon;
grant execute on function siga_private.current_user_id() to authenticated;
grant execute on function siga_private.is_admin() to authenticated;

drop policy if exists siga_units_read_admin_or_assigned on public.siga_units;
drop policy if exists siga_units_insert_admin on public.siga_units;
drop policy if exists siga_units_update_admin on public.siga_units;

create policy siga_units_read_admin_or_assigned
  on public.siga_units
  for select
  to authenticated
  using (
    (select siga_private.is_admin())
    or exists (
      select 1
      from public.siga_user_unit_permissions as permission
      where permission.unit_id = siga_units.id
        and permission.user_id = (select siga_private.current_user_id())
        and permission.permissions @> '{"units.read": true}'::jsonb
    )
  );

create policy siga_units_insert_admin
  on public.siga_units
  for insert
  to authenticated
  with check ((select siga_private.is_admin()));

create policy siga_units_update_admin
  on public.siga_units
  for update
  to authenticated
  using ((select siga_private.is_admin()))
  with check ((select siga_private.is_admin()));

drop policy if exists siga_unit_permissions_read_own_or_admin on public.siga_user_unit_permissions;
drop policy if exists siga_unit_permissions_insert_admin on public.siga_user_unit_permissions;
drop policy if exists siga_unit_permissions_update_admin on public.siga_user_unit_permissions;
drop policy if exists siga_unit_permissions_delete_admin on public.siga_user_unit_permissions;

create policy siga_unit_permissions_read_own_or_admin
  on public.siga_user_unit_permissions
  for select
  to authenticated
  using (
    user_id = (select siga_private.current_user_id())
    or (select siga_private.is_admin())
  );

create policy siga_unit_permissions_insert_admin
  on public.siga_user_unit_permissions
  for insert
  to authenticated
  with check ((select siga_private.is_admin()));

create policy siga_unit_permissions_update_admin
  on public.siga_user_unit_permissions
  for update
  to authenticated
  using ((select siga_private.is_admin()))
  with check ((select siga_private.is_admin()));

create policy siga_unit_permissions_delete_admin
  on public.siga_user_unit_permissions
  for delete
  to authenticated
  using ((select siga_private.is_admin()));

-- SIGA member records do not yet carry a unit_id, so keep them restricted to administrators
-- until unit-scoped member access is implemented.
drop policy if exists "Authenticated users can delete SIGA members" on public.siga_members;
drop policy if exists "Authenticated users can insert SIGA members" on public.siga_members;
drop policy if exists "Authenticated users can read SIGA members" on public.siga_members;
drop policy if exists "Authenticated users can update SIGA members" on public.siga_members;

create policy siga_members_admin_only
  on public.siga_members
  for all
  to authenticated
  using ((select siga_private.is_admin()))
  with check ((select siga_private.is_admin()));

