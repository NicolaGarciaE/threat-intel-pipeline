-- The start date of the target (var start_date_<target>, CLAUDE.md §5) is the first
-- snapshot_date with both core sources: mart_source_days has both on that day, and
-- no earlier day has raw files of both. The raw files are listed with glob(),
-- without reading them. The failing rows hold only dates.
{{ config(store_failures=true) }}

with loaded as (
    select count(distinct source) as sources
    from {{ ref('mart_source_days') }}
    where snapshot_date = {{ start_date() }}
),

raw_days as (
    select 'kev' as source, {{ snapshot_date_from_filename('kev', 'json', 'file') }} as snapshot_date
    from glob('{{ var("raw_dir_" ~ target.name) }}/{{ var("kev_glob") }}')

    union all

    select 'epss' as source, {{ snapshot_date_from_filename('epss', 'csv.gz', 'file') }} as snapshot_date
    from glob('{{ var("raw_dir_" ~ target.name) }}/{{ var("epss_glob") }}')
)

select 'the start date does not have both sources in mart_source_days' as problem, {{ start_date() }} as snapshot_date
from loaded
where sources <> 2

union all

select 'an earlier day has raw files of both sources' as problem, snapshot_date
from raw_days
where snapshot_date < {{ start_date() }}
group by snapshot_date
having count(distinct source) = 2
