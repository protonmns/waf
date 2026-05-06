import type { CrudFilter, DataProvider, BaseRecord, HttpError } from "@refinedev/core";

import { httpClient } from "../utils/axios";

// ─── VictoriaLogs Refine data provider ────────────────────────────────────────
// Single-resource provider keyed by `resource === "logs"`. All other resources
// fall back to the regular REST data provider.
//
// Translation layer:
//   * Refine `CrudFilter[]` is mapped to a LogsQL expression string so the
//     filter sidebar feels like every other Refine table while the wire
//     format matches what VictoriaLogs expects.
//   * Pagination uses the `limit` parameter — VictoriaLogs has no native
//     offset, so server-side pagination beyond the limit cap is not
//     supported. The table is "first N rows that match the filters".
//   * Time range comes through `meta.timeRange = [start, end]` (RFC3339).
//
// Response shape: VictoriaLogs `/select/logsql/query` returns NDJSON (one
// JSON object per line). We split on `\n`, drop blanks, and JSON.parse
// each surviving line.  Total is approximated by the row count we got
// back — VictoriaLogs cannot give a "total before limit" number cheaply.

const LOGS_QUERY_URL = "/api/v1/logs/query";

const LOGSQL_RESERVED = /[\s"\\:|]/;

/** Quote a LogsQL value when it contains reserved characters. */
const escapeValue = (value: string): string => {
  if (LOGSQL_RESERVED.test(value)) {
    // LogsQL accepts double-quoted strings with `\"` escaping. We don't
    // try to be clever — anything ambiguous is wrapped + escaped.
    return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  return value;
};

/**
 * Convert one Refine filter object to a LogsQL fragment.
 *
 * Returns `null` for filters we don't know how to translate so the caller
 * can simply skip them — the alternative (silently dropping them) would
 * surprise the user, but throwing would be too aggressive when the FE
 * passes filters that come from a generic component.
 */
const filterToLogsQL = (filter: CrudFilter): string | null => {
  if (!("field" in filter) || filter.value === undefined || filter.value === "" || filter.value === null) {
    return null;
  }
  const field = filter.field;
  const value = String(filter.value);

  // Free-text search: dedicated synthetic field that compiles to a bare
  // LogsQL token, exercising VictoriaLogs' full-text search across `_msg`.
  if (field === "search" || field === "_msg" || field === "q") {
    return escapeValue(value);
  }

  // Raw LogsQL escape hatch — used by the "Advanced" toggle in the FE.
  if (field === "raw") {
    return value;
  }

  switch (filter.operator) {
    case "eq":
    case undefined:
      return `${field}:${escapeValue(value)}`;
    case "contains":
      return `${field}:${escapeValue(`*${value}*`)}`;
    case "ne":
      return `NOT ${field}:${escapeValue(value)}`;
    default:
      return null;
  }
};

/**
 * Combine a list of Refine filters into a single LogsQL expression.
 * Adjacent fragments are AND-ed together (LogsQL whitespace = AND).
 */
const buildLogsQL = (filters: CrudFilter[] | undefined): string => {
  if (!filters || filters.length === 0) {
    // Empty query is rejected by the proxy; fall back to a wildcard so
    // the empty-state on the FE just shows the most recent rows.
    return "*";
  }
  const parts = filters
    .map((f) => filterToLogsQL(f))
    .filter((p): p is string => p !== null && p.length > 0);
  return parts.length === 0 ? "*" : parts.join(" ");
};

const toHttpError = (err: unknown): HttpError => {
  const axiosErr = err as {
    response?: { status?: number; data?: { error?: string; message?: string } };
    message?: string;
  };
  return {
    message:
      axiosErr.response?.data?.error ??
      axiosErr.response?.data?.message ??
      axiosErr.message ??
      "Network error",
    statusCode: axiosErr.response?.status ?? 500,
  };
};

/**
 * Parse VictoriaLogs' newline-delimited JSON response into a row array.
 *
 * Robust to trailing newlines, blank lines, and individual line parse
 * failures — a single corrupt line shouldn't poison the whole table.
 */
const parseNdjson = (body: string): BaseRecord[] => {
  if (!body) return [];
  const rows: BaseRecord[] = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed) as BaseRecord);
    } catch {
      // Skip — log line is malformed; UI surfaces row count, not byte fidelity.
    }
  }
  return rows;
};

const unsupported = (op: string) => async (): Promise<never> => {
  throw {
    message: `VictoriaLogs data provider: ${op} is read-only`,
    statusCode: 405,
  } satisfies HttpError;
};

export const victoriaLogsDataProvider: DataProvider = {
  getApiUrl: () => LOGS_QUERY_URL,

  getList: async ({ filters, pagination, meta }) => {
    const query = buildLogsQL(filters);
    const limit = Math.min(
      pagination?.mode === "off" ? 5000 : pagination?.pageSize ?? 100,
      5000,
    );

    const params: Record<string, string | number> = { query, limit };
    const range = meta?.timeRange as [string?, string?] | undefined;
    if (range?.[0]) params.start = range[0];
    if (range?.[1]) params.end = range[1];

    try {
      const resp = await httpClient.get(LOGS_QUERY_URL, {
        params,
        // VictoriaLogs returns NDJSON; let axios hand us the raw text so we
        // can parse line-by-line. Skipping `transformResponse` would let
        // axios try to JSON.parse the whole body and throw.
        transformResponse: [(data: string) => data],
      });
      const body = typeof resp.data === "string" ? resp.data : String(resp.data ?? "");
      const rows = parseNdjson(body);
      return { data: rows as never, total: rows.length };
    } catch (err) {
      throw toHttpError(err);
    }
  },

  getOne: unsupported("getOne"),
  create: unsupported("create"),
  update: unsupported("update"),
  deleteOne: unsupported("deleteOne"),

  custom: async ({ url, method, query }) => {
    try {
      const resp = await httpClient.request({
        url: url || LOGS_QUERY_URL,
        method: method ?? "get",
        params: query,
      });
      return { data: resp.data as never };
    } catch (err) {
      throw toHttpError(err);
    }
  },
};

// Re-exports useful for tests and downstream tooling.
export { buildLogsQL, escapeValue, filterToLogsQL, parseNdjson };
