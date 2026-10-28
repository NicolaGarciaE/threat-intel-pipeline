-- The dateAdded of a CVE does not change in the KEV history. Questions 1 and 3 use
-- the dateAdded of its first snapshot (decided in session 3); a change is reported
-- as a warning because it describes history, which cannot be corrected without
-- touching data/raw/ (CLAUDE.md §3).
{{ config(severity='warn') }}

select
    cve_id,
    count(distinct date_added) as date_added_values,
    min(date_added) as earliest,
    max(date_added) as latest
from {{ ref('mart_kev_history') }}
group by cve_id
having count(distinct date_added) > 1
