{#
  Start date of the history (CLAUDE.md §5): the first snapshot_date with both core
  sources correct, one per target (var start_date_<target> in dbt_project.yml). No
  mart holds a day before it. A target without the var fails to parse, and a value
  that is not YYYY-MM-DD stops dbt before running anything.
#}
{% macro start_date() -%}
{{ date_literal(var("start_date_" ~ target.name), "var start_date_" ~ target.name) }}
{%- endmacro %}
