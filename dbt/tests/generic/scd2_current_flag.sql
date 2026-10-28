{# SCD2 (CLAUDE.md §5): is_current is true if and only if valid_to is null. #}
{% test scd2_current_flag(model) %}
select cve_id, valid_from, valid_to, is_current
from {{ model }}
where is_current is distinct from (valid_to is null)
{% endtest %}
