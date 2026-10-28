-- Days missing from each source (CLAUDE.md §5; rule decided in session 3): every
-- calendar day from start_date() to the last day of that source in
-- mart_source_days without data of that source. The histories assume that nothing
-- changed on these days. A source that stops publishing has no trailing gap here:
-- source freshness and Pipeline health report it as stale. Rebuilt from
-- mart_source_days on every run.
{{ config(materialized='table') }}

with last_days as (
    select source, max(snapshot_date) as last_day
    from {{ ref('mart_source_days') }}
    group by source
),

calendar as (
    select source, cast(day as date) as snapshot_date
    from (
        select source, unnest(generate_series({{ start_date() }}, last_day, interval 1 day)) as day
        from last_days
    )
)

select calendar.source, calendar.snapshot_date
from calendar
left join {{ ref('mart_source_days') }} as loaded
    on loaded.source = calendar.source and loaded.snapshot_date = calendar.snapshot_date
where loaded.snapshot_date is null
