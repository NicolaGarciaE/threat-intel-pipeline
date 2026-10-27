{#
  loaded_at_query of a raw source for dbt source freshness. It lists the raw
  files with glob(), without reading them, and returns the end of the day of
  the latest snapshot_date (its next midnight, as a UTC TIMESTAMP: dbt rejects
  a DATE). So "warn after 1 day" means more than 1 whole calendar day without a
  new file. No file gives NULL, which dbt treats as infinitely old: error.
#}
{% macro raw_files_loaded_at(source_name, extension) -%}
select max(cast({{ snapshot_date_from_filename(source_name, extension, 'file') }} as timestamp) + interval 1 day)
from glob('{{ var("raw_dir_" ~ target.name) }}/{{ var(source_name ~ "_glob") }}')
{%- endmacro %}
