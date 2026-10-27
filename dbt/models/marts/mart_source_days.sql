-- Days loaded into the marts: one row per source and snapshot_date, from
-- start_date() on, with the rows of that day in staging (CLAUDE.md §5). The
-- calendar of mart_source_gaps and the guard of the incremental marts, which
-- depend on it. Incremental, per source: only the days after the last one loaded,
-- read with a date constant so DuckDB opens only their raw files.
-- It depends on the manifests too, so that a failure of
-- assert_staging_rows_match_manifests skips it and every mart: dbt skips a node
-- after a test with several independent parents only if the node depends on all
-- of them (stg_kev, stg_epss and raw.manifest).
-- depends_on: {{ source('raw', 'manifest') }}
{{ config(materialized='incremental', incremental_strategy='delete+insert', unique_key=['source', 'snapshot_date']) }}

{%- set since = {"kev": none, "epss": none} -%}
{%- if is_incremental() -%}
{%- for source_name in ["kev", "epss"] -%}
{%- do since.update({source_name: watermark("snapshot_date", "source = '" ~ source_name ~ "'")}) -%}
{%- endfor -%}
{%- do check_no_late_raw_files(since) -%}
{%- endif %}

select 'kev' as source, snapshot_date, count(*) as rows
from {{ ref('stg_kev') }}
where snapshot_date >= {{ start_date() }}
{%- if since.kev is not none %}
    and snapshot_date > {{ since.kev }}
{%- endif %}
group by snapshot_date

union all

select 'epss' as source, snapshot_date, count(*) as rows
from {{ ref('stg_epss') }}
where snapshot_date >= {{ start_date() }}
{%- if since.epss is not none %}
    and snapshot_date > {{ since.epss }}
{%- endif %}
group by snapshot_date
