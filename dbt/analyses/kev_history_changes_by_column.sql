-- Local diagnosis of the noise of the KEV history (CLAUDE.md §12: review planned
-- for about 2026-11-25). For every watched column of mart_kev_history (all the
-- columns but cve_id and the period ones), how many period changes it causes: a
-- CVE's period that starts on the day the previous one ended, with that column
-- different (a CVE that left and returned is not a change). For notes and
-- short_description, a change that only differs in spaces or letter case is
-- counted apart from a change of content; a null against an empty text counts as
-- content. One period change can count in several columns. dbt build never runs
-- analyses. KEV is CC0, so the output can be shown:
--   uv run dbt show --project-dir dbt --profiles-dir dbt --target real --select kev_history_changes_by_column --limit 20
{%- set watched = [] -%}
{%- if execute -%}
{%- for column in adapter.get_columns_in_relation(ref('mart_kev_history'))
    if column.name not in ["cve_id", "valid_from", "valid_to", "is_current"] -%}
{%- do watched.append(column.name) -%}
{%- endfor -%}
{%- endif -%}
{%- set texts = ["notes", "short_description"] %}

with changes as (
    select
        current_period.cve_id,
        current_period.valid_from as changed_on
        {%- for column in watched %},
        previous_period.{{ column }} as previous_{{ column }},
        current_period.{{ column }} as current_{{ column }}
        {%- endfor %}
    from {{ ref('mart_kev_history') }} as current_period
    join {{ ref('mart_kev_history') }} as previous_period
        on previous_period.cve_id = current_period.cve_id
        and previous_period.valid_to = current_period.valid_from
)

select
    'any watched column' as column_name,
    count(*) as period_changes,
    cast(null as bigint) as spaces_or_case_only,
    cast(null as bigint) as content
from changes
{%- for column in watched %}

union all

select
    '{{ column }}' as column_name,
    count(*) filter (where previous_{{ column }} is distinct from current_{{ column }}) as period_changes,
    {%- if column in texts %}
    count(*) filter (where previous_{{ column }} is distinct from current_{{ column }}
        and lower(trim(regexp_replace(previous_{{ column }}, '\s+', ' ', 'g')))
            = lower(trim(regexp_replace(current_{{ column }}, '\s+', ' ', 'g')))) as spaces_or_case_only,
    count(*) filter (where lower(trim(regexp_replace(previous_{{ column }}, '\s+', ' ', 'g')))
        is distinct from lower(trim(regexp_replace(current_{{ column }}, '\s+', ' ', 'g')))) as content
    {%- else %}
    null as spaces_or_case_only,
    null as content
    {%- endif %}
from changes
{%- endfor %}
