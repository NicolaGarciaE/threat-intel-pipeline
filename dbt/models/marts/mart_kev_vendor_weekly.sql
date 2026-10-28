-- Question 3 (CLAUDE.md §6): CVEs added to KEV per ISO week of their dateAdded and
-- vendor (trimmed), over the whole catalog and every CVE ever in the KEV history,
-- with the published vendorProject names behind each vendor. The KEV launch week
-- (2021-W44) is flagged, not removed. Rebuilt from mart_kev_additions every run.
{{ config(materialized='table') }}

select
    week_start,
    iso_year,
    iso_week,
    vendor,
    count(*) as cves,
    list(distinct vendor_project order by vendor_project) as published_names,
    is_kev_launch_week
from {{ ref('mart_kev_additions') }}
group by week_start, iso_year, iso_week, vendor, is_kev_launch_week
