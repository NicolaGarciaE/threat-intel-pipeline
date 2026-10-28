{#
  relationships (CLAUDE.md §6) of an SCD2 history with its staging model: every
  key of a period that starts on or after test_since() exists in staging on those
  days. Both sides are read with that date constant, so DuckDB opens only those
  raw files; dbt's native relationships test would read every raw file of
  stg_epss on every run.
#}
{% test relationships_to_staging(model, column_name, source_name) %}
with child as (
    select distinct {{ column_name }} as value
    from {{ model }}
    where {{ column_name }} is not null
        and valid_from >= {{ test_since() }}
),

parent as (
    select distinct cve_id as value
    from {{ ref("stg_" ~ source_name) }}
    where snapshot_date >= {{ test_since() }}
)

select child.value as {{ column_name }}
from child
left join parent on parent.value = child.value
where parent.value is null
{% endtest %}
