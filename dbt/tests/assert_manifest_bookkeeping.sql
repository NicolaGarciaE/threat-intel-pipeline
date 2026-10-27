-- Warnings about the manifests themselves. They describe history, which cannot
-- be fixed without touching data/raw/ (append-only), so they warn instead of
-- failing: an error here would keep the pipeline red forever.
-- - unreadable manifest: ignored by every check, as in session 1;
-- - a day with staging rows and no readable ok manifest (session 1 exits with
--   code 4 when it cannot write the manifest): its rows cannot be compared;
-- - a day whose latest manifest marks the source failed although its raw file
--   is read: a later attempt found that file failing the raw tests.
{{ config(severity='warn') }}

with entries as (
    {{ manifest_entries() }}
),

staging as (
    {{ staging_rows_per_day() }}
),

latest_ok as (
    select source, snapshot_date, manifest
    from entries
    where readable and status = 'ok'
    qualify row_number() over (partition by source, snapshot_date order by run_started_at desc) = 1
),

latest_readable as (
    select source, snapshot_date, manifest, status
    from entries
    where readable
    qualify row_number() over (partition by source, snapshot_date order by run_started_at desc) = 1
)

select distinct
    'unreadable manifest' as problem,
    cast(null as varchar) as source,
    snapshot_date,
    manifest,
    unreadable_reason as detail
from entries
where not readable

union all

select
    'no readable ok manifest for this day' as problem,
    staging.source,
    staging.snapshot_date,
    cast(null as varchar) as manifest,
    cast(null as varchar) as detail
from staging
left join latest_ok
    on staging.source = latest_ok.source and staging.snapshot_date = latest_ok.snapshot_date
where latest_ok.manifest is null

union all

select
    'the latest manifest of the day marks the source failed' as problem,
    staging.source,
    staging.snapshot_date,
    latest_readable.manifest,
    cast(null as varchar) as detail
from staging
join latest_readable
    on staging.source = latest_readable.source and staging.snapshot_date = latest_readable.snapshot_date
where latest_readable.status = 'failed'
