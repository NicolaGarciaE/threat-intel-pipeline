-- Question 3 trend (decided in session 3): per vendor (trimmed), the CVEs added to
-- KEV in the last 52 complete ISO weeks and in the 52 before them, as counts with
-- their window totals and as shares, and the differences in CVEs and in share
-- points. The windows end before the ISO week of the last KEV snapshot (from the
-- data, not the clock), so the current partial week is left out, and so is the KEV
-- launch week. A share is null when its window has no CVEs. Rebuilt every run.
{{ config(materialized='table') }}

with reference as (
    select
        max(snapshot_date) as reference_day,
        cast(date_trunc('week', max(snapshot_date)) as date) as current_week_start
    from {{ ref('mart_source_days') }}
    where source = 'kev'
),

windows as (
    select
        reference_day,
        cast(current_week_start - interval 52 week as date) as last_52_from,
        current_week_start as last_52_to,
        cast(current_week_start - interval 104 week as date) as previous_52_from,
        cast(current_week_start - interval 52 week as date) as previous_52_to
    from reference
),

per_vendor as (
    select
        additions.vendor,
        count(*) filter (where additions.week_start >= windows.last_52_from
                         and additions.week_start < windows.last_52_to) as cves_last_52,
        count(*) filter (where additions.week_start >= windows.previous_52_from
                         and additions.week_start < windows.previous_52_to) as cves_previous_52
    from {{ ref('mart_kev_additions') }} as additions
    cross join windows
    where not additions.is_kev_launch_week
    group by additions.vendor
    having cves_last_52 + cves_previous_52 > 0
),

totals as (
    select
        cast(sum(cves_last_52) as bigint) as total_last_52,
        cast(sum(cves_previous_52) as bigint) as total_previous_52
    from per_vendor
)

select
    per_vendor.vendor,
    per_vendor.cves_last_52,
    totals.total_last_52,
    per_vendor.cves_last_52 / nullif(totals.total_last_52, 0) as share_last_52,
    per_vendor.cves_previous_52,
    totals.total_previous_52,
    per_vendor.cves_previous_52 / nullif(totals.total_previous_52, 0) as share_previous_52,
    per_vendor.cves_last_52 - per_vendor.cves_previous_52 as diff_cves,
    100 * (per_vendor.cves_last_52 / nullif(totals.total_last_52, 0)
        - per_vendor.cves_previous_52 / nullif(totals.total_previous_52, 0)) as diff_share_points,
    windows.last_52_from,
    windows.last_52_to,
    windows.previous_52_from,
    windows.previous_52_to,
    windows.reference_day
from per_vendor
cross join totals
cross join windows
