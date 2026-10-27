-- EPSS scores: one row per CVE and snapshot_date (CLAUDE.md §5). A view over the
-- raw files, so it takes no space in the database.
-- epss and percentile are read as text and converted to an exact DECIMAL only if
-- their text has the format FIRST writes; any other value fails every query that
-- reads them. The message carries no data, so no EPSS value reaches a log:
-- analyses/epss_unexpected_number_format.sql lists the offending rows locally.
{{ config(materialized='view') }}

select
    {{ snapshot_date_from_filename('epss', 'csv.gz') }} as snapshot_date,
    cve as cve_id,
    {{ strict_cast('epss', format_epss_number(), 'decimal(6,5)',
        "'stg_epss: epss has an unexpected number format; see analyses/epss_unexpected_number_format.sql'") }} as epss,
    {{ strict_cast('percentile', format_epss_number(), 'decimal(6,5)',
        "'stg_epss: percentile has an unexpected number format; see analyses/epss_unexpected_number_format.sql'") }} as percentile
from {{ source('raw', 'epss') }}
