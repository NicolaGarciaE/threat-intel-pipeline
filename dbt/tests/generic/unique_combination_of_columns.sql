{#
  Fails for every combination of the given columns that appears more than once.
  dbt's native unique test only checks one column.
#}
{% test unique_combination_of_columns(model, combination_of_columns) %}
select
    {{ combination_of_columns | join(', ') }},
    count(*) as occurrences
from {{ model }}
group by {{ combination_of_columns | join(', ') }}
having count(*) > 1
{% endtest %}
