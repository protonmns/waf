import { useEffect, useState } from "react";
import { Card, Space, DatePicker, Select, Input, Button, Tooltip, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import dayjs, { type Dayjs } from "dayjs";

import { httpClient } from "../../utils/axios";

// ─── Public types ─────────────────────────────────────────────────────────────

export type LogsRange = [string, string]; // [startISO, endISO]

export interface LogsFilterState {
  eventType?: string;
  tiers: string[];
  ruleName?: string;
  clientIp?: string;
  search?: string;
  range: LogsRange;
}

// Defaults: last 1 hour, no other filters.
export const defaultLogsFilters = (): LogsFilterState => {
  const end = dayjs();
  const start = end.subtract(1, "hour");
  return {
    tiers: [],
    range: [start.toISOString(), end.toISOString()],
  };
};

// ─── Server-supplied dropdown values ─────────────────────────────────────────

interface StreamsResponse {
  event_type?: string;
  rule_name?: string;
  tier?: string;
}

/** Best-effort parser for the `field_values` body. */
const parseFieldValues = (raw: string | undefined): string[] => {
  if (!raw) return [];
  const out: string[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      // VictoriaLogs returns `{"field":"<value>","hits":N}` per row.
      const field = obj.field;
      if (typeof field === "string" && field.length > 0) {
        out.push(field);
      }
    } catch {
      // skip
    }
  }
  // De-dupe + sort for stable dropdowns.
  return Array.from(new Set(out)).sort();
};

// ─── Component ────────────────────────────────────────────────────────────────

interface Props {
  value: LogsFilterState;
  onChange: (next: LogsFilterState) => void;
  onApply: () => void;
  loading: boolean;
}

/**
 * Sidebar filter panel for the logs viewer. Holds local state for free-text
 * inputs (so they don't fire a query on every keystroke) and bubbles a
 * coalesced `LogsFilterState` up via `onChange` only when the user clicks
 * Apply.
 */
export const LogsFilters: React.FC<Props> = ({ value, onChange, onApply, loading }) => {
  const [eventTypes, setEventTypes] = useState<string[]>([]);
  const [ruleNames, setRuleNames] = useState<string[]>([]);
  const [tiers, setTiers] = useState<string[]>([]);

  // Local mirrors so typing in the IP / search inputs doesn't cascade.
  const [clientIp, setClientIp] = useState(value.clientIp ?? "");
  const [search, setSearch] = useState(value.search ?? "");

  useEffect(() => {
    void (async () => {
      try {
        const resp = await httpClient.get<StreamsResponse>("/api/v1/logs/streams");
        setEventTypes(parseFieldValues(resp.data.event_type));
        setRuleNames(parseFieldValues(resp.data.rule_name));
        setTiers(parseFieldValues(resp.data.tier));
      } catch {
        // Streams endpoint failure is non-fatal: drop downs just stay empty
        // and the user can still type values directly.
      }
    })();
  }, []);

  const handleApply = () => {
    onChange({ ...value, clientIp: clientIp || undefined, search: search || undefined });
    onApply();
  };

  const handleRangeChange = (vals: [Dayjs | null, Dayjs | null] | null) => {
    if (!vals?.[0] || !vals?.[1]) return;
    onChange({ ...value, range: [vals[0].toISOString(), vals[1].toISOString()] });
  };

  const presetRange = (delta: { hours?: number; days?: number }) => {
    const end = dayjs();
    const start = delta.hours ? end.subtract(delta.hours, "hour") : end.subtract(delta.days ?? 1, "day");
    onChange({ ...value, range: [start.toISOString(), end.toISOString()] });
  };

  return (
    <Card size="small" title={<Typography.Text strong>Filters</Typography.Text>}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Space.Compact block>
          <Button size="small" onClick={() => presetRange({ hours: 1 })}>1h</Button>
          <Button size="small" onClick={() => presetRange({ hours: 6 })}>6h</Button>
          <Button size="small" onClick={() => presetRange({ hours: 24 })}>24h</Button>
          <Button size="small" onClick={() => presetRange({ days: 7 })}>7d</Button>
        </Space.Compact>

        <DatePicker.RangePicker
          showTime
          value={[dayjs(value.range[0]), dayjs(value.range[1])]}
          onChange={handleRangeChange}
          style={{ width: "100%" }}
        />

        <Select
          allowClear
          placeholder="Event Type"
          value={value.eventType}
          onChange={(v) => onChange({ ...value, eventType: v })}
          options={[
            { value: "block", label: "Block" },
            { value: "allow", label: "Allow" },
            { value: "rate_limit", label: "Rate Limit" },
            { value: "challenge", label: "Challenge" },
            { value: "log_only", label: "Log Only" },
            ...eventTypes
              .filter((v) => !["block", "allow", "rate_limit", "challenge", "log_only"].includes(v))
              .map((v) => ({ value: v, label: v })),
          ]}
          style={{ width: "100%" }}
        />

        <Select
          mode="multiple"
          allowClear
          placeholder="Tier"
          value={value.tiers}
          onChange={(v) => onChange({ ...value, tiers: v })}
          options={(tiers.length > 0 ? tiers : ["Critical", "High", "Medium", "CatchAll"]).map((v) => ({
            value: v,
            label: v,
          }))}
          style={{ width: "100%" }}
        />

        <Select
          showSearch
          allowClear
          placeholder="Rule Name"
          value={value.ruleName}
          onChange={(v) => onChange({ ...value, ruleName: v })}
          options={ruleNames.map((v) => ({ value: v, label: v }))}
          style={{ width: "100%" }}
        />

        <Tooltip title="Exact match — supports both IPv4 and IPv6">
          <Input
            placeholder="Client IP"
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            onPressEnter={handleApply}
            allowClear
          />
        </Tooltip>

        <Input.Search
          placeholder="Free-text search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onSearch={handleApply}
          enterButton={false}
          allowClear
        />

        <Button
          type="primary"
          onClick={handleApply}
          icon={<ReloadOutlined spin={loading} />}
          loading={loading}
          block
        >
          Apply Filters
        </Button>
      </Space>
    </Card>
  );
};

// ─── LogsQL builder (shared with LogsQueryBar) ───────────────────────────────

/** Translate the structured filter state into a Refine-compatible filter array. */
export const filtersToCrud = (state: LogsFilterState): import("@refinedev/core").CrudFilter[] => {
  const out: import("@refinedev/core").CrudFilter[] = [];
  if (state.eventType) {
    out.push({ field: "event_type", operator: "eq", value: state.eventType });
  }
  if (state.ruleName) {
    out.push({ field: "rule_name", operator: "eq", value: state.ruleName });
  }
  if (state.clientIp) {
    out.push({ field: "client_ip", operator: "eq", value: state.clientIp });
  }
  // Multiple tiers OR-merge — we render them as a single LogsQL fragment
  // wrapped in parens so the filter joins with AND against the rest.
  if (state.tiers.length > 0) {
    const expr = state.tiers.map((t) => `tier:${t}`).join(" OR ");
    out.push({ field: "raw", operator: "eq", value: `(${expr})` });
  }
  if (state.search) {
    out.push({ field: "search", operator: "eq", value: state.search });
  }
  return out;
};

/** Render a human-readable LogsQL preview from the filter state. */
export const filtersToLogsQL = (state: LogsFilterState): string => {
  const parts: string[] = [];
  if (state.eventType) parts.push(`event_type:${state.eventType}`);
  if (state.ruleName) parts.push(`rule_name:${JSON.stringify(state.ruleName)}`);
  if (state.clientIp) parts.push(`client_ip:${JSON.stringify(state.clientIp)}`);
  if (state.tiers.length > 0) {
    parts.push(`(${state.tiers.map((t) => `tier:${t}`).join(" OR ")})`);
  }
  if (state.search) parts.push(JSON.stringify(state.search));
  return parts.length === 0 ? "*" : parts.join(" ");
};
