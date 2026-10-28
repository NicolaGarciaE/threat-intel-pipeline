{#
  SCD type 2 history of a staging model (CLAUDE.md §5), shared by
  mart_kev_history and mart_epss_history: one row per cve_id and period in which
  its watched columns did not change, with valid_from (included), valid_to
  (excluded; null while current) and is_current.
  - Days are the snapshot_dates of the source from start_date() on. A day without
    a file is not a day: it closes nothing, and mart_source_gaps lists it.
  - A period starts on the first observation of a key, when the key was absent on
    the previous day (it returns: a new period, even with the same values), or
    when a watched value changes. The values are compared as one struct with IS
    DISTINCT FROM: null-safe, and lists compared as published (order included).
  - valid_to is the next day after the last observation of the period: the day a
    value changed or the key was first missing.
  - Incremental runs: the watermark is the last date with an event in the table,
    max(coalesce(valid_to, valid_from)). The open periods are the seed, placed on
    that day, and only the later days are read; rereading days without events
    changes nothing. Only new or closed periods are written: with unique_key
    (cve_id, valid_from), delete+insert replaces the open row that a period closes.
#}
{% macro scd2_history(staging, source_name, watched_columns) -%}
{%- set since = watermark("coalesce(valid_to, valid_from)") if is_incremental() else none -%}
{%- if since is not none -%}
{%- do check_days_match_source_days(staging, source_name, "snapshot_date > " ~ since) -%}
{%- endif -%}
{%- set row_values = watched_values(watched_columns) -%}

with observed as (
    select cve_id, snapshot_date, {{ watched_columns | join(", ") }}, cast(null as date) as seed_valid_from
    from {{ staging }}
    where snapshot_date >= {{ start_date() }}
    {%- if since is not none %}
        and snapshot_date > {{ since }}

    union all

    -- The seed: the open periods of the table, placed on the watermark day.
    select cve_id, {{ since }}, {{ watched_columns | join(", ") }}, valid_from
    from {{ this }}
    where valid_to is null
    {%- endif %}
),

days as (
    select
        snapshot_date,
        row_number() over (order by snapshot_date) as day_number,
        lead(snapshot_date) over (order by snapshot_date) as next_day
    from (select distinct snapshot_date from observed)
),

compared as (
    select
        observed.*,
        days.day_number,
        lag(days.day_number) over by_key as previous_day_number,
        {{ row_values }} is distinct from lag({{ row_values }}) over by_key as values_changed
    from observed
    join days on days.snapshot_date = observed.snapshot_date
    window by_key as (partition by observed.cve_id order by observed.snapshot_date)
),

numbered as (
    select
        *,
        sum(cast(starts_period as integer)) over (
            partition by cve_id order by snapshot_date rows unbounded preceding
        ) as period_number
    from (
        select
            *,
            previous_day_number is null
                or previous_day_number <> day_number - 1
                or values_changed as starts_period
        from compared
    )
),

periods as (
    select
        cve_id,
        period_number,
        coalesce(min(seed_valid_from), min(snapshot_date)) as valid_from,
        max(snapshot_date) as last_day,
        bool_or(seed_valid_from is not null) as from_seed
    from numbered
    group by cve_id, period_number
)

-- The values of each period come from its first row.
select
    numbered.cve_id,
    {%- for column in watched_columns %}
    numbered.{{ column }},
    {%- endfor %}
    periods.valid_from,
    days.next_day as valid_to,
    days.next_day is null as is_current
from numbered
join periods on periods.cve_id = numbered.cve_id and periods.period_number = numbered.period_number
join days on days.snapshot_date = periods.last_day
where numbered.starts_period
    -- An open period that goes on unchanged is already in the table.
    and not (periods.from_seed and days.next_day is null)
{%- endmacro %}

{# The watched columns as one struct, to compare them at once with IS DISTINCT FROM. #}
{% macro watched_values(columns) -%}
struct_pack({% for column in columns %}{{ column }} := {{ column }}{{ ", " if not loop.last }}{% endfor %})
{%- endmacro %}

{#
  Guard of the incremental marts that read staging: the days that match
  days_filter (a condition on snapshot_date with date constants, such as the days
  after a watermark) must be exactly the days of this source in mart_source_days,
  each with the rows it recorded. Otherwise the run stops before writing anything:
  a recorded day whose raw file is missing or reads differently would close every
  open period of a history (or mark CVEs not_scored), and a day that
  mart_source_days has not accepted could be a late file.
#}
{% macro check_days_match_source_days(staging, source_name, days_filter) -%}
{%- set query -%}
with recorded as (
    select snapshot_date, rows
    from {{ ref("mart_source_days") }}
    where source = '{{ source_name }}' and {{ days_filter }}
),

staged as (
    select snapshot_date, count(*) as rows
    from {{ staging }}
    where {{ days_filter }}
    group by snapshot_date
)

select
    strftime(coalesce(recorded.snapshot_date, staged.snapshot_date), '%Y-%m-%d') as snapshot_date,
    coalesce(recorded.rows, 0) as recorded_rows,
    coalesce(staged.rows, 0) as staging_rows
from recorded
full outer join staged on staged.snapshot_date = recorded.snapshot_date
where recorded.rows is distinct from staged.rows
order by 1
{%- endset -%}
{%- set mismatches = run_query(query) -%}
{%- if mismatches.rows | length > 0 -%}
{%- set details = [] -%}
{%- for row in mismatches.rows -%}
{%- do details.append(row[0] ~ " (" ~ row[1] ~ " rows in mart_source_days, " ~ row[2] ~ " in staging)") -%}
{%- endfor -%}
{{ exceptions.raise_compiler_error(
    this.identifier ~ ": the " ~ source_name ~ " days where " ~ days_filter ~ " do not match mart_source_days: "
    ~ details | join(", ") ~ ". Restore the missing raw files or build mart_source_days first;"
    ~ " to recompute everything, run dbt build --full-refresh.") }}
{%- endif -%}
{%- endmacro %}
