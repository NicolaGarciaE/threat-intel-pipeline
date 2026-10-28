{#
  Guard of mart_source_days (CLAUDE.md §5): stops an incremental run if a raw file
  on disk belongs to a day its source has already passed (from start_date() to the
  last day loaded, since[source]) but was never loaded. Each ingest run only
  writes the raw files of its own day, so this should never happen; loading such
  a file now would leave the incremental marts different from a rebuild. It lists
  the files with glob(), without reading them.
#}
{% macro check_no_late_raw_files(since) -%}
{%- set checked = [] -%}
{%- for source_name, extension in [("kev", "json"), ("epss", "csv.gz")] if since[source_name] is not none -%}
{%- do checked.append((source_name, extension)) -%}
{%- endfor -%}
{%- if checked -%}
{%- set query -%}
select files.source, strftime(files.snapshot_date, '%Y-%m-%d') as snapshot_date
from (
    {%- for source_name, extension in checked %}
    {{ "union all" if not loop.first }}
    select '{{ source_name }}' as source, snapshot_date
    from (
        select {{ snapshot_date_from_filename(source_name, extension, "file") }} as snapshot_date
        from glob('{{ var("raw_dir_" ~ target.name) }}/{{ var(source_name ~ "_glob") }}')
    )
    where snapshot_date between {{ start_date() }} and {{ since[source_name] }}
    {%- endfor %}
) as files
left join {{ this }} as loaded
    on loaded.source = files.source and loaded.snapshot_date = files.snapshot_date
where loaded.snapshot_date is null
order by 1, 2
{%- endset -%}
{%- set late = run_query(query) -%}
{%- if late.rows | length > 0 -%}
{%- set files = [] -%}
{%- for row in late.rows -%}
{%- do files.append(row[0] ~ " " ~ row[1]) -%}
{%- endfor -%}
{{ exceptions.raise_compiler_error(
    this.identifier ~ ": raw files of days already passed were never loaded: " ~ files | join(", ")
    ~ ". Loading them now would make the incremental marts differ from a rebuild:"
    ~ " run dbt build --full-refresh.") }}
{%- endif -%}
{%- endif -%}
{%- endmacro %}
