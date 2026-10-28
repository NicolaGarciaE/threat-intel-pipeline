-- Question 1 (CLAUDE.md §6, three states decided in session 3): a row has a
-- percentile if and only if its status is scored.
select cve_id, days_before, coverage_status
from {{ ref('mart_epss_before_kev') }}
where (percentile is not null) <> (coverage_status = 'scored')
