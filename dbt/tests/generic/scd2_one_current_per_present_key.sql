{#
  SCD2 (CLAUDE.md §6): exactly one current row (is_current) for each key present
  on the last day of its source in mart_source_days, and none for any other key.
  That day is read as a date constant, so DuckDB opens only its raw file.
#}
{% test scd2_one_current_per_present_key(model, source_name) %}
{%- set source_days = ref("mart_source_days") -%}
{%- set last_day = watermark("snapshot_date", "source = '" ~ source_name ~ "'", source_days) if execute else none -%}
with current_rows as (
    select cve_id, count(*) as current_rows
    from {{ model }}
    where is_current
    group by cve_id
),

present as (
    select distinct cve_id
    from {{ ref("stg_" ~ source_name) }}
    where snapshot_date = {{ "null" if last_day is none else last_day }}
)

select
    coalesce(current_rows.cve_id, present.cve_id) as cve_id,
    coalesce(current_rows.current_rows, 0) as current_rows,
    present.cve_id is not null as present_on_last_day
from current_rows
full outer join present on present.cve_id = current_rows.cve_id
where coalesce(current_rows.current_rows, 0) <> case when present.cve_id is null then 0 else 1 end
{% endtest %}
