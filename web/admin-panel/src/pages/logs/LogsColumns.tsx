import { Button, Space, Tag } from "antd";
import { FilterOutlined } from "@ant-design/icons";
import type { ColumnType } from "antd/es/table";

import { fmtDateTime } from "../../utils/format";
import type { LogRow } from "./LogsTable";

/**
 * Built-in (well-known) column definition.
 *
 *   - `id`     — row field key (also localStorage / DnD identifier)
 *   - `label`  — picker label (e.g. "Client IP")
 *   - `def`    — AntD column descriptor
 *
 * The wrapper struct exists so the picker can show user-friendly labels
 * for short field keys without polluting the AntD column object with
 * non-AntD properties.
 */
export interface BuiltinColumn {
  id: string;
  label: string;
  def: ColumnType<LogRow>;
}

const eventTypeColor = (eventType: string | undefined): string => {
  switch (eventType) {
    case "block":
      return "red";
    case "rate_limit":
      return "gold";
    case "challenge":
      return "purple";
    case "log_only":
      return "blue";
    case "allow":
      return "green";
    default:
      return "default";
  }
};

/**
 * Build the canonical built-in column list. The render closures capture
 * the upstream filter callbacks, so this is a function (not a static
 * const) called from the consumer with `useMemo`.
 */
export const buildBuiltinColumns = (
  onFilterClientIp: (ip: string) => void,
  onFilterRuleName: (rule: string) => void,
): BuiltinColumn[] => [
  {
    id: "_time",
    label: "Time",
    def: {
      title: "Time",
      dataIndex: "_time",
      width: 180,
      render: (v: unknown) => (
        <span style={{ color: "#8c8c8c", fontSize: 12 }}>
          {typeof v === "string" ? fmtDateTime(v) : "—"}
        </span>
      ),
    },
  },
  {
    id: "event_type",
    label: "Event",
    def: {
      title: "Event",
      dataIndex: "event_type",
      width: 100,
      render: (v: unknown) =>
        typeof v === "string" && v ? <Tag color={eventTypeColor(v)}>{v}</Tag> : <Tag>—</Tag>,
    },
  },
  {
    id: "rule_name",
    label: "Rule",
    def: {
      title: "Rule",
      dataIndex: "rule_name",
      width: 200,
      ellipsis: true,
      render: (v: unknown) =>
        typeof v === "string" && v ? (
          <Space size={4}>
            <span title={v}>{v}</span>
            <Button
              size="small"
              type="text"
              icon={<FilterOutlined />}
              onClick={() => onFilterRuleName(v)}
              title="Filter by this rule"
            />
          </Space>
        ) : (
          "—"
        ),
    },
  },
  {
    id: "client_ip",
    label: "Client IP",
    def: {
      title: "Client IP",
      dataIndex: "client_ip",
      width: 170,
      render: (v: unknown) =>
        typeof v === "string" && v ? (
          <Space size={4}>
            <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>{v}</span>
            <Button
              size="small"
              type="text"
              icon={<FilterOutlined />}
              onClick={() => onFilterClientIp(v)}
              title="Filter by this IP"
            />
          </Space>
        ) : (
          "—"
        ),
    },
  },
  {
    id: "host",
    label: "Host",
    def: { title: "Host", dataIndex: "host", width: 160, ellipsis: true },
  },
  {
    id: "tier",
    label: "Tier",
    def: {
      title: "Tier",
      dataIndex: "tier",
      width: 100,
      render: (v: unknown) => (typeof v === "string" && v ? <Tag>{v}</Tag> : "—"),
    },
  },
  {
    id: "detail",
    label: "Detail",
    def: {
      title: "Detail",
      dataIndex: "detail",
      ellipsis: true,
      render: (v: unknown, row: LogRow) => {
        const display = (typeof v === "string" ? v : undefined) ?? row._msg;
        return (
          <span
            style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}
            title={typeof display === "string" ? display : ""}
          >
            {typeof display === "string" && display ? display : "—"}
          </span>
        );
      },
    },
  },
];

/**
 * Generic cell renderer for ad-hoc / custom-pinned columns.
 *
 * Strings, numbers, booleans → printed as-is.
 * Objects / arrays           → compact JSON, full value in tooltip.
 * Empty / null / undefined   → muted em dash.
 */
export const renderGenericCell = (value: unknown): React.ReactNode => {
  if (value === null || value === undefined || value === "") {
    return <span style={{ color: "#bfbfbf" }}>—</span>;
  }
  const text =
    typeof value === "string" || typeof value === "number" || typeof value === "boolean"
      ? String(value)
      : safeStringify(value);
  return (
    <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }} title={text}>
      {text}
    </span>
  );
};

const safeStringify = (v: unknown): string => {
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
};
