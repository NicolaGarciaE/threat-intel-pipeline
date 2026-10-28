-- Question 2, independent check (asked in session 3): the 7-day pairs recomputed
-- from stg_epss directly, reading the EPSS files of each covered day d and of d-7,
-- must give exactly the counts of mart_epss_risers_daily and the rows of
-- mart_epss_risers, which are read from the EPSS history. Only the covered days
-- from test_since() on; their files and those of d-7 are read as date constants.
-- The failing rows hold no EPSS values.
{%- set dates = [] -%}
{%- if execute -%}
{%- set covered = run_query(
    "select strftime(snapshot_date, '%Y-%m-%d'), strftime(previous_date, '%Y-%m-%d') from "
    ~ ref('mart_epss_risers_daily') ~ " where coverage_status = 'covered' and snapshot_date >= " ~ test_since()) -%}
{%- for day, previous_day in covered.rows -%}
{%- do dates.append(date_literal(day, "a covered day")) -%}
{%- do dates.append(date_literal(previous_day, "the day before a covered day")) -%}
{%- endfor -%}
{%- endif %}

with daily as (
    select *
    from {{ ref('mart_epss_risers_daily') }}
    where coverage_status = 'covered' and snapshot_date >= {{ test_since() }}
),

scores as (
    select snapshot_date, cve_id, epss
    from {{ ref('stg_epss') }}
    where {{ "snapshot_date in (" ~ dates | unique | join(", ") ~ ")" if dates else "false" }}
),

pairs as (
    select daily.snapshot_date, current_day.cve_id, previous_day.epss as previous_epss, current_day.epss, daily.threshold
    from daily
    join scores as current_day on current_day.snapshot_date = daily.snapshot_date
    join scores as previous_day
        on previous_day.snapshot_date = daily.previous_date and previous_day.cve_id = current_day.cve_id
),

recomputed as (
    select
        snapshot_date,
        count(*) as cves_both_days,
        count(*) filter (where epss <> previous_epss) as cves_changed,
        count(*) filter (where epss - previous_epss >= threshold) as cves_risen
    from pairs
    group by snapshot_date
),

expected_risers as (
    select snapshot_date, cve_id, previous_epss, epss
    from pairs
    where epss - previous_epss >= threshold
),

actual_risers as (
    select snapshot_date, cve_id, previous_epss, epss
    from {{ ref('mart_epss_risers') }}
    where snapshot_date in (select snapshot_date from daily)
),

missing as (
    select * from expected_risers
    except all
    select * from actual_risers
),

unexpected as (
    select * from actual_risers
    except all
    select * from expected_risers
)

select daily.snapshot_date, cast(null as varchar) as cve_id, 'the counts differ from staging' as problem
from daily
left join recomputed on recomputed.snapshot_date = daily.snapshot_date
where daily.cves_both_days is distinct from coalesce(recomputed.cves_both_days, 0)
    or daily.cves_changed is distinct from coalesce(recomputed.cves_changed, 0)
    or daily.cves_risen is distinct from coalesce(recomputed.cves_risen, 0)

union all

select snapshot_date, cve_id, 'a riser in staging is missing from mart_epss_risers' as problem
from missing

union all

select snapshot_date, cve_id, 'a riser of mart_epss_risers is not a riser in staging' as problem
from unexpected
