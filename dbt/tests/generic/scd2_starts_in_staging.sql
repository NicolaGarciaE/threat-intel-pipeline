{#
  SCD2: every period starts on a staging row of its key on valid_from, with the
  same values in every watched column (all the columns of the history but cve_id,
  valid_from, valid_to and is_current), compared as one struct: null-safe, lists
  as published. Only the periods and staging days from test_since() on are
  checked, read with that date constant. The failing rows hold no values.
#}
{% test scd2_starts_in_staging(model, source_name) %}
{%- set watched = [] -%}
{%- if execute -%}
{%- for column in adapter.get_columns_in_relation(model)
    if column.name not in ["cve_id", "valid_from", "valid_to", "is_current"] -%}
{%- do watched.append(column.name) -%}
{%- endfor -%}
{%- endif -%}
with periods as (
    select cve_id, valid_from, {{ watched_values(watched) }} as row_values
    from {{ model }}
    where valid_from >= {{ test_since() }}
),

staged as (
    select cve_id, snapshot_date, {{ watched_values(watched) }} as row_values
    from {{ ref("stg_" ~ source_name) }}
    where snapshot_date >= {{ test_since() }}
)

select periods.cve_id, periods.valid_from, staged.cve_id is null as missing_in_staging
from periods
left join staged
    on staged.cve_id = periods.cve_id and staged.snapshot_date = periods.valid_from
where staged.cve_id is null
    or staged.row_values is distinct from periods.row_values
{% endtest %}
