{# SCD2 (CLAUDE.md §6): a closed period ends after it starts, valid_from < valid_to. #}
{% test scd2_valid_range(model) %}
select cve_id, valid_from, valid_to
from {{ model }}
where valid_to is not null
    and not valid_from < valid_to
{% endtest %}
