{#
  Threshold T of question 2 (CLAUDE.md §6), var epss_rise_threshold: a rise of
  epss in 7 days counts if it is at least T. An exact DECIMAL(6,5), like epss;
  anything but a number from 0 to 1 with up to 5 decimals stops dbt.
#}
{% macro epss_rise_threshold() -%}
{%- set text = var("epss_rise_threshold") | string -%}
{%- if not modules.re.fullmatch("0([.][0-9]{1,5})?|1([.]0{1,5})?", text) -%}
{{ exceptions.raise_compiler_error("var epss_rise_threshold must be a number from 0 to 1 with up to 5 decimals, got '" ~ text ~ "'") }}
{%- endif -%}
cast('{{ text }}' as decimal(6,5))
{%- endmacro %}

{#
  Guard of the incremental question 2 marts: the rows already in the table were
  computed with the current threshold. Otherwise the run stops, so that a table
  never mixes two thresholds: a new threshold needs dbt build --full-refresh.
#}
{% macro check_rise_threshold() -%}
{%- set other = run_query("select count(*) from " ~ this ~ " where threshold <> " ~ epss_rise_threshold()) -%}
{%- if other.rows[0][0] > 0 -%}
{{ exceptions.raise_compiler_error(
    this.identifier ~ ": rows computed with another threshold than var epss_rise_threshold ("
    ~ var("epss_rise_threshold") ~ "); rebuild with dbt build --full-refresh.") }}
{%- endif -%}
{%- endmacro %}

{#
  The 7-day pairs of question 2 (CLAUDE.md §6), as two CTEs (days, pairs) read
  from the EPSS history, without opening any raw file (decided in session 3):
  - days: every EPSS day d of mart_source_days (after since, if given), its d-7,
    and whether d-7 has an EPSS file too. If it has not, d is no_coverage: d-7 is
    never replaced by another day.
  - pairs: for the days with d-7, every CVE present on both days and its epss on
    each. On a day with an EPSS file, a period of the history covers the day if and
    only if the CVE was in that file with that epss. in_kev: a period of
    mart_kev_history covers d (KEV in our history on that day).
  tests/assert_epss_rises_match_staging.sql recomputes the pairs from stg_epss.
#}
{% macro epss_rise_pairs(since) -%}
days as (
    select
        epss_days.snapshot_date,
        epss_days.snapshot_date - 7 as previous_date,
        previous_days.snapshot_date is not null as has_previous
    from {{ ref('mart_source_days') }} as epss_days
    left join {{ ref('mart_source_days') }} as previous_days
        on previous_days.source = 'epss' and previous_days.snapshot_date = epss_days.snapshot_date - 7
    where epss_days.source = 'epss'
    {%- if since is not none %}
        and epss_days.snapshot_date > {{ since }}
    {%- endif %}
),

pairs as (
    select
        days.snapshot_date,
        current_period.cve_id,
        previous_period.epss as previous_epss,
        current_period.epss,
        kev.cve_id is not null as in_kev
    from days
    join {{ ref('mart_epss_history') }} as current_period
        on current_period.valid_from <= days.snapshot_date
        and (current_period.valid_to is null or current_period.valid_to > days.snapshot_date)
    join {{ ref('mart_epss_history') }} as previous_period
        on previous_period.cve_id = current_period.cve_id
        and previous_period.valid_from <= days.previous_date
        and (previous_period.valid_to is null or previous_period.valid_to > days.previous_date)
    left join {{ ref('mart_kev_history') }} as kev
        on kev.cve_id = current_period.cve_id
        and kev.valid_from <= days.snapshot_date
        and (kev.valid_to is null or kev.valid_to > days.snapshot_date)
    where days.has_previous
)
{%- endmacro %}
