{#
  Fails for every non-null value that does not fully match pattern (RE2 syntax,
  no anchors needed). NULLs are left to not_null.
#}
{% test matches_regex(model, column_name, pattern) %}
select {{ column_name }}
from {{ model }}
where {{ column_name }} is not null
    and not regexp_full_match({{ column_name }}, '{{ pattern }}')
{% endtest %}
