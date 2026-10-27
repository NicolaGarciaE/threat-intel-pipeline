{#
  First snapshot_date that the EPSS and manifest tests check: --vars "test_since: YYYY-MM-DD"
  (the same text in PowerShell and bash). Unset: every day (CI and rebuilds).
  A date constant, so DuckDB reads only the raw files from that date on.
  Any other format stops dbt while it parses the project, before running anything:
  the manifest tests call this macro. The where config of the stg_epss tests
  (models/staging/_stg_models.yml) reads the same var, with the same default.
#}
{% macro test_since() -%}
{%- set value = var("test_since", "0001-01-01") | string -%}
{%- if not modules.re.fullmatch("[0-9]{4}-[0-9]{2}-[0-9]{2}", value) -%}
{{ exceptions.raise_compiler_error("test_since must be YYYY-MM-DD, got '" ~ value ~ "'") }}
{%- endif -%}
date '{{ value }}'
{%- endmacro %}
