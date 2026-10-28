-- Question 2 (CLAUDE.md §6): the CVEs whose epss rose at least the threshold
-- (epss_rise_threshold) in 7 days, one row per day d and CVE, with both epss values
-- (exact decimals), the rise and whether the CVE was in KEV on d. Only CVEs present
-- on d and d-7, and only days whose d-7 has an EPSS file; mart_epss_risers_daily
-- has the counts. Read from the EPSS history (macros/epss_rise.sql). Incremental:
-- the EPSS days after the last one with a riser; rereading a day writes the same rows.
{{ config(materialized='incremental', incremental_strategy='delete+insert', unique_key=['snapshot_date', 'cve_id']) }}

{%- set since = none -%}
{%- if is_incremental() -%}
{%- set since = watermark("snapshot_date") -%}
{%- do check_rise_threshold() -%}
{%- endif %}

with {{ epss_rise_pairs(since) }}

select
    snapshot_date,
    cve_id,
    previous_epss,
    epss,
    epss - previous_epss as rise,
    in_kev,
    {{ epss_rise_threshold() }} as threshold
from pairs
where epss - previous_epss >= {{ epss_rise_threshold() }}
