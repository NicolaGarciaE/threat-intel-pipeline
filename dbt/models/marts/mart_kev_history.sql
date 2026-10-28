-- History of the KEV catalog (CLAUDE.md §5): one row per cve_id and period in
-- which its 11 record fields did not change. catalog_version and date_released
-- describe the file, not the CVE, so they are not watched (decided in session 3).
-- The logic is in macros/scd2_history.sql.
-- depends_on: {{ ref('mart_source_days') }}
{{ config(materialized='incremental', incremental_strategy='delete+insert', unique_key=['cve_id', 'valid_from']) }}

{{ scd2_history(ref('stg_kev'), 'kev', [
    'vendor_project', 'product', 'vulnerability_name', 'date_added', 'short_description',
    'required_action', 'due_date', 'known_ransomware_campaign_use', 'forensic_triage', 'notes', 'cwes'
]) }}
