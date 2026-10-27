{#
  Fails for every value outside [min_value, max_value], both ends included.
  NULLs are left to not_null.
#}
{% test value_between(model, column_name, min_value, max_value) %}
select {{ column_name }}
from {{ model }}
where {{ column_name }} < {{ min_value }}
    or {{ column_name }} > {{ max_value }}
{% endtest %}
