{#
  snapshot_date of a raw file, from its name <source>_<YYYY-MM-DD>.<ext>.
  Accepts both path separators: DuckDB returns '\' on Windows and '/' on Linux.
  The cast is strict: a name that does not match, or an invalid date, fails the query.
#}
{% macro snapshot_date_from_filename(source_name, extension, column='filename') -%}
cast(regexp_extract({{ column }}, '(^|[/\\]){{ source_name }}_([0-9]{4}-[0-9]{2}-[0-9]{2})[.]{{ extension | replace('.', '[.]') }}$', 2) as date)
{%- endmacro %}
