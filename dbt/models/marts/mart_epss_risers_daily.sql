-- Question 2 (CLAUDE.md §6), one row per EPSS day d of the history: whether d-7
-- has an EPSS file too (covered) or not (no_coverage, with null counts), and for
-- the covered days the CVEs on both days (the denominator), how many changed epss
-- in those 7 days, and how many rose at least the threshold (epss_rise_threshold),
-- all of them and those in KEV on d. Read from the EPSS history
-- (macros/epss_rise.sql), without opening raw files. Incremental: the EPSS days
-- after the last one in the table.
{{ config(materialized='incremental', incremental_strategy='delete+insert', unique_key=['snapshot_date']) }}

{%- set since = none -%}
{%- if is_incremental() -%}
{%- set since = watermark("snapshot_date") -%}
{%- do check_rise_threshold() -%}
{%- endif %}

with {{ epss_rise_pairs(since) }},

counts as (
    select
        snapshot_date,
        count(*) as cves_both_days,
        count(*) filter (where epss <> previous_epss) as cves_changed,
        count(*) filter (where epss - previous_epss >= {{ epss_rise_threshold() }}) as cves_risen,
        count(*) filter (where epss - previous_epss >= {{ epss_rise_threshold() }} and in_kev) as cves_risen_in_kev
    from pairs
    group by snapshot_date
)

select
    days.snapshot_date,
    days.previous_date,
    case when days.has_previous then 'covered' else 'no_coverage' end as coverage_status,
    {{ epss_rise_threshold() }} as threshold,
    case when days.has_previous then coalesce(counts.cves_both_days, 0) end as cves_both_days,
    case when days.has_previous then coalesce(counts.cves_changed, 0) end as cves_changed,
    case when days.has_previous then coalesce(counts.cves_risen, 0) end as cves_risen,
    case when days.has_previous then coalesce(counts.cves_risen_in_kev, 0) end as cves_risen_in_kev
from days
left join counts on counts.snapshot_date = days.snapshot_date
