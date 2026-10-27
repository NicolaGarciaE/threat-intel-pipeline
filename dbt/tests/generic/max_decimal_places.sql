{#
  For number texts written as FIRST EPSS writes them (format_epss_number()).
  Fails for every non-null text with more than `places` decimals, and for every
  text that does not match that format, so decimals are never counted on a
  malformed value. It runs on the text because the cast to DECIMAL(6,5) would
  round the excess away.
  Decimals of the value: fraction digits without trailing zeros, plus the
  negative exponent (1.5e-06 has 1 + 6 = 7). Exact for any length.
  Only the raw files from test_since() on are read: the where config cannot
  call macros, and the source has no snapshot_date column.
#}
{% test max_decimal_places(model, column_name, places) %}
with checked as (
    select
        {{ column_name }} as value,
        regexp_full_match({{ column_name }}, '{{ format_epss_number() }}') as format_ok,
        length(rtrim(regexp_extract({{ column_name }}, '^[0-9]+[.]?([0-9]*)', 1), '0')) as fraction_digits,
        regexp_extract({{ column_name }}, 'e-([0-9]+)$', 1) as negative_exponent
    from {{ model }}
    where {{ column_name }} is not null
        and {{ snapshot_date_from_filename('epss', 'csv.gz') }} >= {{ test_since() }}
)

select value
from checked
where not format_ok
    or fraction_digits + cast(coalesce(nullif(negative_exponent, ''), '0') as integer) > {{ places }}
{% endtest %}
