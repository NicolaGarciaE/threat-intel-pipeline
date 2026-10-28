-- Question 1 (CLAUDE.md §5 and §6, decisions of session 3): for every CVE of
-- mart_kev_additions with dateAdded on or after the start date, the EPSS
-- percentile 30 and 7 days before its dateAdded and on that day, one row each.
-- The status of a row is no_coverage when the history has no EPSS file of that
-- date, not_scored when it has one but the CVE is not in it, and scored otherwise,
-- with the published percentile. Incremental: the CVEs not in the table yet, and
-- those with a no_coverage row whose date now has an EPSS file (a same-day retry).
-- stg_epss is read only on the dates needed, written as date constants.
{{ config(materialized='incremental', incremental_strategy='delete+insert', unique_key=['cve_id', 'days_before']) }}

{%- set batch -%}
select cve_id, first_seen, date_added
from {{ ref('mart_kev_additions') }}
where date_added >= {{ start_date() }}
{%- if is_incremental() %}
    and (
        cve_id not in (select cve_id from {{ this }})
        or cve_id in (
            select stored.cve_id
            from {{ this }} as stored
            join {{ ref('mart_source_days') }} as epss_days
                on epss_days.source = 'epss' and epss_days.snapshot_date = stored.target_date
            where stored.coverage_status = 'no_coverage'
        )
    )
{%- endif %}
{%- endset -%}

{%- set days_filter = "false" -%}
{%- if execute -%}
{%- set dates = run_query(
    "select distinct strftime(batch.date_added - offsets.days_before, '%Y-%m-%d') from (" ~ batch ~ ") as batch"
    ~ " cross join (values (30), (7), (0)) as offsets (days_before)"
    ~ " join " ~ ref('mart_source_days') ~ " as epss_days on epss_days.source = 'epss'"
    ~ " and epss_days.snapshot_date = batch.date_added - offsets.days_before order by 1") -%}
{%- if dates.rows | length > 0 -%}
{%- set literals = [] -%}
{%- for row in dates.rows -%}
{%- do literals.append(date_literal(row[0], "a date needed by " ~ this.identifier)) -%}
{%- endfor -%}
{%- set days_filter = "snapshot_date in (" ~ literals | join(", ") ~ ")" -%}
{%- do check_days_match_source_days(ref('stg_epss'), 'epss', days_filter) -%}
{%- endif -%}
{%- endif %}

with batch as (
    {{ batch }}
),

targets as (
    select
        batch.cve_id,
        batch.date_added,
        batch.first_seen,
        offsets.days_before,
        batch.date_added - offsets.days_before as target_date
    from batch
    cross join (values (30), (7), (0)) as offsets (days_before)
),

epss_days as (
    select snapshot_date
    from {{ ref('mart_source_days') }}
    where source = 'epss'
),

scores as (
    select snapshot_date, cve_id, percentile
    from {{ ref('stg_epss') }}
    where {{ days_filter }}
)

select
    targets.cve_id,
    targets.date_added,
    targets.first_seen,
    targets.days_before,
    targets.target_date,
    case
        when epss_days.snapshot_date is null then 'no_coverage'
        when scores.cve_id is null then 'not_scored'
        else 'scored'
    end as coverage_status,
    scores.percentile
from targets
left join epss_days on epss_days.snapshot_date = targets.target_date
left join scores on scores.snapshot_date = targets.target_date and scores.cve_id = targets.cve_id
