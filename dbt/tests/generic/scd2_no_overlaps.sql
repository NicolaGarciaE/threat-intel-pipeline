{#
  SCD2 (CLAUDE.md §6): the periods of a key never overlap. Ordered by valid_from,
  each period ends (valid_to) on or before the next one starts, so an open period
  (valid_to null) can only be the last one.
#}
{% test scd2_no_overlaps(model) %}
select cve_id, valid_from, valid_to, next_valid_from
from (
    select
        cve_id,
        valid_from,
        valid_to,
        lead(valid_from) over (partition by cve_id order by valid_from) as next_valid_from
    from {{ model }}
)
where next_valid_from is not null
    and (valid_to is null or valid_to > next_valid_from)
{% endtest %}
