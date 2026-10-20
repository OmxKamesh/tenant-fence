-- OPTIONAL: run manually only in your disposable local/staging project.
-- This tests this fixture table's policy, NOT your production tables' policies.
-- Create two synthetic Auth users first; replace UUID placeholders below.
create table public.tenant_fence_fixtures (
  id text primary key,
  owner_id uuid not null references auth.users(id),
  marker text not null
);
alter table public.tenant_fence_fixtures enable row level security;
grant select on public.tenant_fence_fixtures to authenticated;
create policy own_fixture_only on public.tenant_fence_fixtures
for select to authenticated using ((select auth.uid()) = owner_id);
insert into public.tenant_fence_fixtures (id, owner_id, marker) values
('tenant-fence-a', 'REPLACE_WITH_USER_A_UUID', 'tenant-fence-marker-a'),
('tenant-fence-b', 'REPLACE_WITH_USER_B_UUID', 'tenant-fence-marker-b');
-- For your own table, seed equivalent synthetic rows using its actual membership
-- model. Do not replace your app's authorization model with this example.
