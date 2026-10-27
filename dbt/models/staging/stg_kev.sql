-- KEV catalog: one row per CVE and snapshot_date (CLAUDE.md §5).
-- Texts are kept exactly as published. Dates are converted only if their text
-- has the exact format; any other value fails the build. No row is filtered out:
-- the tests detect the problems.
{{ config(materialized='table') }}

with catalog as (
    select
        filename,
        catalogVersion,
        dateReleased,
        unnest(vulnerabilities) as v
    from {{ source('raw', 'kev') }}
)

select
    {{ snapshot_date_from_filename('kev', 'json') }} as snapshot_date,
    v.cveID as cve_id,
    v.vendorProject as vendor_project,
    v.product as product,
    v.vulnerabilityName as vulnerability_name,
    {{ strict_cast('v.dateAdded', format_date(), 'date',
        "concat('stg_kev: dateAdded is not YYYY-MM-DD for ', v.cveID, ' in ', filename, ': ', v.dateAdded)") }} as date_added,
    v.shortDescription as short_description,
    v.requiredAction as required_action,
    {{ strict_cast('v.dueDate', format_date(), 'date',
        "concat('stg_kev: dueDate is not YYYY-MM-DD for ', v.cveID, ' in ', filename, ': ', v.dueDate)") }} as due_date,
    v.knownRansomwareCampaignUse as known_ransomware_campaign_use,
    v.forensicTriage as forensic_triage,
    v.notes as notes,
    v.cwes as cwes,
    catalogVersion as catalog_version,
    {{ strict_cast('dateReleased', format_timestamp_utc(), 'timestamptz',
        "concat('stg_kev: dateReleased is not an ISO 8601 UTC timestamp in ', filename, ': ', dateReleased)") }} as date_released
from catalog
