-- Every CVE ever in the KEV history (CLAUDE.md §6, questions 1 and 3), also those
-- that left the catalog later: one row per CVE with the dateAdded and the
-- vendorProject of its first snapshot (decided in session 3), the vendor trimmed of
-- leading and trailing spaces (staging keeps the published text), and the ISO week
-- of that dateAdded. The week of the KEV launch (2021-11-03, ISO week 2021-W44) is
-- flagged: questions on trends leave it out. Rebuilt from mart_kev_history on
-- every run.
{{ config(materialized='table') }}

with first_periods as (
    select cve_id, valid_from as first_seen, date_added, vendor_project
    from {{ ref('mart_kev_history') }}
    qualify row_number() over (partition by cve_id order by valid_from) = 1
),

current_cves as (
    select distinct cve_id
    from {{ ref('mart_kev_history') }}
    where is_current
)

select
    first_periods.cve_id,
    first_periods.first_seen,
    first_periods.date_added,
    first_periods.vendor_project,
    trim(first_periods.vendor_project) as vendor,
    isoyear(first_periods.date_added) as iso_year,
    week(first_periods.date_added) as iso_week,
    cast(date_trunc('week', first_periods.date_added) as date) as week_start,
    cast(date_trunc('week', first_periods.date_added) as date) = date '2021-11-01' as is_kev_launch_week,
    current_cves.cve_id is not null as in_kev
from first_periods
left join current_cves on current_cves.cve_id = first_periods.cve_id
