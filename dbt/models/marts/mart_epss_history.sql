-- History of EPSS scores (CLAUDE.md §5): one row per cve_id and period in which
-- its epss did not change. epss is an exact DECIMAL(6,5), so 3e-05 and 0.00003 are
-- the same value. percentile is not historized. The logic is in
-- macros/scd2_history.sql.
-- depends_on: {{ ref('mart_source_days') }}
{{ config(materialized='incremental', incremental_strategy='delete+insert', unique_key=['cve_id', 'valid_from']) }}

{{ scd2_history(ref('stg_epss'), 'epss', ['epss']) }}
