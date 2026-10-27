{#
  Converts text to data_type only if it fully matches pattern; any other value
  fails the query with error(message). DuckDB's CAST alone accepts too much
  ('2026-10-23 garbage' as DATE, ' 0.5' or '+0.5' as DECIMAL).
  NULL stays NULL, so the not_null tests report it instead of this error.
  message is a SQL expression; it must never contain EPSS values.
#}
{% macro strict_cast(expression, pattern, data_type, message) -%}
case
    when {{ expression }} is null then null
    when regexp_full_match({{ expression }}, '{{ pattern }}') then cast({{ expression }} as {{ data_type }})
    else error({{ message }})
end
{%- endmacro %}

{# Exact text formats seen in the sources (session 2, 2026-10-27). #}

{% macro format_date() -%}
[0-9]{4}-[0-9]{2}-[0-9]{2}
{%- endmacro %}

{# The final Z makes the cast an instant in UTC, whatever the session time zone. #}
{% macro format_timestamp_utc() -%}
[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?Z
{%- endmacro %}

{# EPSS numbers: plain decimal (0.04753, 0.0, 1.0) or Python-style scientific notation (1e-05). #}
{% macro format_epss_number() -%}
[0-9]+[.][0-9]+|[0-9]([.][0-9]+)?e-[0-9]{2,}
{%- endmacro %}
