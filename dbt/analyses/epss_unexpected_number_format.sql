-- Local diagnosis for "stg_epss: ... unexpected number format": lists the EPSS
-- rows whose epss or percentile text does not match the format stg_epss expects.
-- dbt build never runs analyses. Its output shows EPSS values, so run it only
-- locally, never in CI (CLAUDE.md §4):
--   uv run dbt show --project-dir dbt --profiles-dir dbt --target real --select epss_unexpected_number_format --limit 100
with raw as (
    select
        {{ snapshot_date_from_filename('epss', 'csv.gz') }} as snapshot_date,
        cve,
        epss,
        percentile
    from {{ source('raw', 'epss') }}
)

select snapshot_date, cve, 'epss' as column_name, epss as value
from raw
where epss is not null and not regexp_full_match(epss, '{{ format_epss_number() }}')

union all

select snapshot_date, cve, 'percentile' as column_name, percentile as value
from raw
where percentile is not null and not regexp_full_match(percentile, '{{ format_epss_number() }}')

order by snapshot_date, cve, column_name
