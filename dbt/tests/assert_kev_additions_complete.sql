-- Questions 1 and 3: mart_kev_additions has one row per CVE ever in the KEV history,
-- including those that left the catalog, and only the KEV launch week is flagged:
-- its ISO year and week are 2021 and 44.
with history as (
    select distinct cve_id from {{ ref('mart_kev_history') }}
),

additions as (
    select * from {{ ref('mart_kev_additions') }}
),

missing as (
    select cve_id from history
    except
    select cve_id from additions
),

extra as (
    select cve_id from additions
    except
    select cve_id from history
)

select 'in mart_kev_history but not in mart_kev_additions' as problem, cve_id from missing
union all
select 'in mart_kev_additions but not in mart_kev_history' as problem, cve_id from extra
union all
select 'the launch week flag does not match ISO week 2021-W44' as problem, cve_id
from additions
where is_kev_launch_week <> (iso_year = 2021 and iso_week = 44)
