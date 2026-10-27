{#
  One row per manifest file and source ('kev', 'epss'), for the tests that
  compare staging with the manifests (tests/assert_*manifest*.sql).

  Manifests are read as text, so one that cannot be read is classified as
  unreadable, with a reason, instead of breaking the query: as in session 1, it
  is not used, not touched, and reported (CLAUDE.md section 4).

  The reference rules are _read_manifest and _check_entry in
  src/threat_intel_pipeline/manifest.py (session 1). Only what these tests need
  is checked here; if those rules change, review this macro.
  snapshot_date and run_started_at come from the file name, as in session 1.
  Both macros keep only the days from test_since() on: singular tests ignore
  the where config, and both sides of the comparison must use the same days.
#}
{% macro manifest_entries() -%}
with files as (
    select
        regexp_extract(filename, 'manifest_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}Z[.]json$') as manifest,
        content
    from {{ source('raw', 'manifest') }}
),

per_source as (
    select
        files.manifest,
        cast(substr(files.manifest, 10, 10) as date) as snapshot_date,
        strptime(substr(files.manifest, 10, 17), '%Y-%m-%d_%H%M%S') as run_started_at,
        files.content,
        sources.source,
        '$.sources.' || sources.source as path
    from files
    cross join (values ('kev'), ('epss')) as sources (source)
),

checked as (
    select
        *,
        -- The first failed check. CASE evaluates each WHEN only on the rows
        -- not matched yet, so no JSON function sees invalid JSON.
        -- json_extract_string, not ->>: in DuckDB ->> binds looser than or, = and <>.
        case
            when not json_valid(content) then 'invalid JSON'
            when json_type(content) <> 'OBJECT' then 'not a JSON object'
            when json_type(content, '$.manifest_version') is distinct from 'UBIGINT'
                or json_extract_string(content, '$.manifest_version') <> '1' then 'manifest_version is not 1'
            when json_extract_string(content, '$.snapshot_date') is distinct from strftime(snapshot_date, '%Y-%m-%d')
                then 'snapshot_date does not match the file name'
            when json_type(content, path) is distinct from 'OBJECT'
                then source || ' entry is missing or not an object'
            when coalesce(json_extract_string(content, path || '.status'), '') not in ('ok', 'failed')
                then source || ' status is not ok or failed'
            when json_extract_string(content, path || '.status') = 'ok'
                and json_type(content, path || '.rows') is distinct from 'UBIGINT'
                then source || ' rows is not a non-negative integer'
            when source = 'kev' and json_extract_string(content, path || '.status') = 'ok'
                and json_type(content, path || '.count') is distinct from 'UBIGINT'
                then 'kev count is not a non-negative integer'
        end as problem
    from per_source
),

reasons as (
    -- As in session 1, a manifest is unreadable if any of its entries is.
    -- distinct: a problem of the whole manifest is found once per source.
    select manifest, string_agg(distinct problem, '; ' order by problem) as unreadable_reason
    from checked
    group by manifest
)

select
    checked.manifest,
    checked.snapshot_date,
    checked.run_started_at,
    checked.source,
    reasons.unreadable_reason is null as readable,
    reasons.unreadable_reason,
    case when reasons.unreadable_reason is null
        then json_extract_string(checked.content, checked.path || '.status') end as status,
    case when reasons.unreadable_reason is null
        then cast(json_extract_string(checked.content, checked.path || '.rows') as bigint) end as rows,
    case when reasons.unreadable_reason is null and checked.source = 'kev'
        then cast(json_extract_string(checked.content, checked.path || '.count') as bigint) end as count
from checked
join reasons using (manifest)
where checked.snapshot_date >= {{ test_since() }}
{%- endmacro %}

{# Rows of each staging model per snapshot_date, from test_since() on. #}
{% macro staging_rows_per_day() -%}
select 'kev' as source, snapshot_date, count(*) as staging_rows
from {{ ref('stg_kev') }}
where snapshot_date >= {{ test_since() }}
group by snapshot_date

union all

select 'epss' as source, snapshot_date, count(*) as staging_rows
from {{ ref('stg_epss') }}
where snapshot_date >= {{ test_since() }}
group by snapshot_date
{%- endmacro %}
