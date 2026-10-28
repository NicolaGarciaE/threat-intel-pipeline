-- Question 1 (CLAUDE.md §6): every CVE of mart_kev_additions with dateAdded on or
-- after the start date has exactly 3 rows, for 30, 7 and 0 days before its
-- dateAdded, with that target date and the dateAdded and first snapshot of
-- mart_kev_additions; no other CVE has rows.
with expected as (
    select
        additions.cve_id,
        additions.date_added,
        additions.first_seen,
        offsets.days_before,
        additions.date_added - offsets.days_before as target_date
    from {{ ref('mart_kev_additions') }} as additions
    cross join (values (30), (7), (0)) as offsets (days_before)
    where additions.date_added >= {{ start_date() }}
),

actual as (
    select cve_id, date_added, first_seen, days_before, target_date
    from {{ ref('mart_epss_before_kev') }}
),

missing as (
    select * from expected
    except all
    select * from actual
),

unexpected as (
    select * from actual
    except all
    select * from expected
)

select 'missing row' as problem, * from missing
union all
select 'unexpected row' as problem, * from unexpected
