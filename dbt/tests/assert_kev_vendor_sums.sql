-- Question 3: the weekly table and the trend add up to mart_kev_additions. The
-- weekly counts per ISO week and vendor are those of mart_kev_additions; the trend
-- windows are the same on every row; each window total is the sum of its vendors
-- and the number of CVEs of mart_kev_additions in that window (launch week left
-- out); and the shares are between 0 and 1.
with additions as (
    select * from {{ ref('mart_kev_additions') }}
),

weekly as (
    select * from {{ ref('mart_kev_vendor_weekly') }}
),

trend as (
    select * from {{ ref('mart_kev_vendor_trend') }}
),

windows as (
    select distinct last_52_from, last_52_to, previous_52_from, previous_52_to, total_last_52, total_previous_52
    from trend
),

weekly_from_additions as (
    select week_start, vendor, count(*) as cves
    from additions
    group by week_start, vendor
),

weekly_differences as (
    (select * from weekly_from_additions except all select week_start, vendor, cves from weekly)
    union all
    (select week_start, vendor, cves from weekly except all select * from weekly_from_additions)
)

select 'the weekly counts differ from mart_kev_additions' as problem, count(*) as rows
from weekly_differences
having count(*) > 0

union all

select 'the trend windows differ between rows' as problem, count(*) as rows
from windows
having count(*) > 1

union all

select 'a window total is not the sum of its vendors' as problem, count(*) as rows
from windows
where total_last_52 <> (select sum(cves_last_52) from trend)
    or total_previous_52 <> (select sum(cves_previous_52) from trend)
having count(*) > 0

union all

select 'a window total differs from mart_kev_additions' as problem, count(*) as rows
from windows
where total_last_52 <> (
        select count(*) from additions
        where not is_kev_launch_week and week_start >= windows.last_52_from and week_start < windows.last_52_to)
    or total_previous_52 <> (
        select count(*) from additions
        where not is_kev_launch_week and week_start >= windows.previous_52_from and week_start < windows.previous_52_to)
having count(*) > 0

union all

select 'a share is not between 0 and 1' as problem, count(*) as rows
from trend
where share_last_52 not between 0 and 1 or share_previous_52 not between 0 and 1
having count(*) > 0
