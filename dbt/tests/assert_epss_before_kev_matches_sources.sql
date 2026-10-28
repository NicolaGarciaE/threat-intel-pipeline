-- Question 1: the status of each row agrees with its sources. no_coverage if and
-- only if the history has no EPSS file of the target date (mart_source_days);
-- otherwise scored, with the same percentile, if the CVE is in stg_epss that day,
-- and not_scored if it is not. Only rows with a target date from test_since() on
-- are checked, and staging is read with that date constant. The failing rows hold
-- no EPSS values.
with checked as (
    select *
    from {{ ref('mart_epss_before_kev') }}
    where target_date >= {{ test_since() }}
),

epss_days as (
    select snapshot_date
    from {{ ref('mart_source_days') }}
    where source = 'epss'
),

scores as (
    select snapshot_date, cve_id, percentile
    from {{ ref('stg_epss') }}
    where snapshot_date >= {{ test_since() }}
),

expected as (
    select
        checked.cve_id,
        checked.days_before,
        case
            when epss_days.snapshot_date is null then 'no_coverage'
            when scores.cve_id is null then 'not_scored'
            else 'scored'
        end as coverage_status,
        scores.percentile
    from checked
    left join epss_days on epss_days.snapshot_date = checked.target_date
    left join scores on scores.snapshot_date = checked.target_date and scores.cve_id = checked.cve_id
)

select
    checked.cve_id,
    checked.days_before,
    checked.target_date,
    checked.coverage_status,
    expected.coverage_status as expected_status,
    checked.percentile is not distinct from expected.percentile as same_percentile
from checked
join expected on expected.cve_id = checked.cve_id and expected.days_before = checked.days_before
where checked.coverage_status is distinct from expected.coverage_status
    or checked.percentile is distinct from expected.percentile
