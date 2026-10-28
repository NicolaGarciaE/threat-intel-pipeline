-- Question 2: the daily counts agree with their days and with the list of risers.
-- A day is covered if and only if d-7 has an EPSS file in mart_source_days; its
-- counts are null if and only if it is not covered; risen in KEV <= risen <=
-- changed <= on both days; risen and risen in KEV equal the rows of
-- mart_epss_risers that day; and every riser rose epss - previous_epss, at least
-- its threshold, on a covered day. The failing rows hold only dates and problems.
with daily as (
    select * from {{ ref('mart_epss_risers_daily') }}
),

epss_days as (
    select snapshot_date
    from {{ ref('mart_source_days') }}
    where source = 'epss'
),

risers as (
    select snapshot_date, count(*) as risen, count(*) filter (where in_kev) as risen_in_kev
    from {{ ref('mart_epss_risers') }}
    group by snapshot_date
)

select daily.snapshot_date, 'the status does not match the EPSS file of d-7' as problem
from daily
left join epss_days on epss_days.snapshot_date = daily.previous_date
where (daily.coverage_status = 'covered') <> (epss_days.snapshot_date is not null)
    or daily.previous_date <> daily.snapshot_date - 7

union all

select snapshot_date, 'the counts are null and the status is covered, or the reverse' as problem
from daily
where (coverage_status = 'covered')
    <> (cves_both_days is not null and cves_changed is not null and cves_risen is not null and cves_risen_in_kev is not null)
    or (coverage_status = 'no_coverage')
    <> (cves_both_days is null and cves_changed is null and cves_risen is null and cves_risen_in_kev is null)

union all

select snapshot_date, 'the counts are out of order' as problem
from daily
where not (cves_risen_in_kev <= cves_risen and cves_risen <= cves_changed and cves_changed <= cves_both_days)

union all

select daily.snapshot_date, 'the counts differ from mart_epss_risers' as problem
from daily
left join risers on risers.snapshot_date = daily.snapshot_date
where daily.coverage_status = 'covered'
    and (daily.cves_risen <> coalesce(risers.risen, 0) or daily.cves_risen_in_kev <> coalesce(risers.risen_in_kev, 0))

union all

select risers.snapshot_date, 'risers on a day that is not covered' as problem
from risers
left join daily on daily.snapshot_date = risers.snapshot_date
where daily.coverage_status is distinct from 'covered'

union all

select snapshot_date, 'a rise is not epss - previous_epss or is below its threshold' as problem
from {{ ref('mart_epss_risers') }}
where rise <> epss - previous_epss or rise < threshold
