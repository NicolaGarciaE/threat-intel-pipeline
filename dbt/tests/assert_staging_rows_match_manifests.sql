-- Staging rows per day against the latest readable manifest of that day with
-- the source ok, in both directions. The manifest rows were counted by Python at
-- download time, independently of DuckDB: a difference means staging lost or
-- added rows (for example, a read option that silently returns 0 rows).
-- Days without such a manifest are warnings in assert_manifest_bookkeeping.
-- With test_since, a source without any row from that date on fails too: every
-- filtered test passes on 0 rows, so a wrong date must not turn the build green.
-- The failing rows hold only metadata (no EPSS values), so they can be stored.
{{ config(store_failures=true) }}

with entries as (
    {{ manifest_entries() }}
),

staging as (
    {{ staging_rows_per_day() }}
),

latest_ok as (
    select source, snapshot_date, manifest, rows as manifest_rows, count as manifest_count
    from entries
    where readable and status = 'ok'
    qualify row_number() over (partition by source, snapshot_date order by run_started_at desc) = 1
),

compared as (
    select
        coalesce(staging.source, latest_ok.source) as source,
        coalesce(staging.snapshot_date, latest_ok.snapshot_date) as snapshot_date,
        staging.staging_rows,
        latest_ok.manifest,
        latest_ok.manifest_rows,
        latest_ok.manifest_count
    from staging
    full outer join latest_ok
        on staging.source = latest_ok.source and staging.snapshot_date = latest_ok.snapshot_date
)

select *, 'rows differ from the manifest' as problem
from compared
where staging_rows <> manifest_rows

union all

select *, 'rows differ from count' as problem
from compared
where source = 'kev' and staging_rows <> manifest_count

union all

select *, 'manifest ok but no rows in staging' as problem
from compared
where staging_rows is null
{% if var("test_since", none) is not none %}

union all

select
    sources.source,
    {{ test_since() }} as snapshot_date,
    0 as staging_rows,
    null as manifest,
    null as manifest_rows,
    null as manifest_count,
    'no rows on or after test_since' as problem
from (values ('kev'), ('epss')) as sources (source)
where not exists (select 1 from staging where staging.source = sources.source)
{% endif %}
