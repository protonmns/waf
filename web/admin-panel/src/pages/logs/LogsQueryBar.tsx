import { useState } from "react";
import { Input, Button, Space, message, Tooltip, Card, Switch } from "antd";
import { CopyOutlined, EditOutlined, EyeOutlined } from "@ant-design/icons";

interface Props {
  /** Current LogsQL preview (from `filtersToLogsQL` upstream). */
  computed: string;
  /** Whether the user has switched to "advanced" raw-LogsQL mode. */
  rawMode: boolean;
  /** Raw LogsQL string when in advanced mode. */
  rawValue: string;
  /** Notified on raw-value changes (does not auto-execute). */
  onRawChange: (value: string) => void;
  /** Toggle raw mode on/off. */
  onModeChange: (raw: boolean) => void;
  /** Run the current effective query. */
  onRun: () => void;
  loading: boolean;
}

/**
 * Top query bar showing the LogsQL expression that will be sent to
 * VictoriaLogs. In "filter mode" (default) this is read-only and
 * computed from the sidebar filters; clicking "Advanced" lets the user
 * edit the LogsQL directly — useful for debugging or when a query
 * shape isn't expressible in the sidebar.
 */
export const LogsQueryBar: React.FC<Props> = ({
  computed,
  rawMode,
  rawValue,
  onRawChange,
  onModeChange,
  onRun,
  loading,
}) => {
  const [, setTick] = useState(0); // local re-render after copy

  const visible = rawMode ? rawValue : computed;

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(visible);
      void message.success("LogsQL copied to clipboard");
      setTick((t) => t + 1);
    } catch {
      void message.error("Clipboard write failed");
    }
  };

  return (
    <Card size="small" bodyStyle={{ padding: "10px 12px" }}>
      <Space.Compact block>
        <Tooltip title={rawMode ? "Switch to filter-driven query" : "Edit raw LogsQL"}>
          <Switch
            checked={rawMode}
            onChange={onModeChange}
            checkedChildren={<EditOutlined />}
            unCheckedChildren={<EyeOutlined />}
          />
        </Tooltip>
        <Input
          value={visible}
          onChange={(e) => onRawChange(e.target.value)}
          disabled={!rawMode}
          placeholder="LogsQL — e.g. event_type:block tier:Critical"
          style={{ fontFamily: "ui-monospace, monospace" }}
          onPressEnter={onRun}
        />
        <Tooltip title="Copy LogsQL">
          <Button icon={<CopyOutlined />} onClick={copyToClipboard} />
        </Tooltip>
        <Button type="primary" onClick={onRun} loading={loading}>
          Run
        </Button>
      </Space.Compact>
    </Card>
  );
};
