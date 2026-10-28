{#
  A date written into SQL as a constant, date 'YYYY-MM-DD', so DuckDB reads only
  the raw files of the days it needs (CLAUDE.md §5). value is a date or a text;
  anything but exactly YYYY-MM-DD stops dbt with an error that names what it was.
  An impossible date in that format (2026-02-30) fails in DuckDB when it reads
  the constant.
#}
{% macro date_literal(value, what) -%}
{%- set text = value | string -%}
{%- if not modules.re.fullmatch("[0-9]{4}-[0-9]{2}-[0-9]{2}", text) -%}
{{ exceptions.raise_compiler_error(what ~ " must be a date YYYY-MM-DD, got '" ~ text ~ "'") }}
{%- endif -%}
date '{{ text }}'
{%- endmacro %}

{#
  Watermark of an incremental model: max(expression) over the rows of its own
  table (or of relation) that match where, as a date constant, or none if there
  are none (the model then processes every day, as on its first run). Call it
  only when is_incremental() is true: that is false while dbt parses, on the
  first run and with --full-refresh, so no query runs then. Tests that need the
  last day of a source pass relation and call it only when execute is true.
#}
{% macro watermark(expression, where="true", relation=none) -%}
{%- set table = this if relation is none else relation -%}
{%- set result = run_query("select max(" ~ expression ~ ") from " ~ table ~ " where " ~ where) -%}
{%- if result.rows | length != 1 or result.columns | length != 1 -%}
{{ exceptions.raise_compiler_error(
    "watermark of " ~ table ~ ": expected 1 row and 1 column, got "
    ~ (result.rows | length) ~ " rows and " ~ (result.columns | length) ~ " columns") }}
{%- endif -%}
{%- set value = result.rows[0][0] -%}
{{ return(none if value is none else date_literal(value, "watermark of " ~ table ~ " (max of " ~ expression ~ ")")) }}
{%- endmacro %}
