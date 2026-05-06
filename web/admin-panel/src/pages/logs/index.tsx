import { useEffect, useMemo, useState } from "react";
import {
  Card,
  Col,
  Row,
  Space,
  Switch,
  Typography,
  Alert,
  Button,
  Statistic,
  message,
} from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useList } from "@refinedev/core";

import {
  LogsFilters,
  defaultLogsFilters,
  filtersToCrud,
  filtersToLogsQL,
  type LogsFilterState,
} from "./LogsFilters";
import { LogsQueryBar } from "./LogsQueryBar";
import { LogsTable, type LogRow } from "./LogsTable";
import { httpClient } from "../../utils/axios";

// ─── Stats hook ──────────────────────────────────────────────────────────────

interface LogsStats {
  count_24h_raw?: string;
  metrics?: string;
}

/** Pull a few quick numbers from the proxy `/api/v1/logs/stats`. */
const useLogsStats = (refreshKey: number): LogsStats => {
  const [stats, setStats] = useState<LogsStats>({});
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const resp = await httpClient.get<LogsStats>("/api/v1/logs/stats");
        if (!cancelled) setStats(resp.data ?? {});
      } catch {
        if (!cancelled) setStats({});
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);
  return stats;
};

/** Heuristic count extraction — VictoriaLogs returns a raw text body. */
const parseTotalFromStats = (raw: string | undefined): number | null => {
  if (!raw) return null;
  // The body looks like `{"total":1234}` or NDJSON with a `total` key.
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof obj.total === "number") return obj.total;
      if (typeof obj.total === "string" && /^\d+$/.test(obj.total)) {
        return Number.parseInt(obj.total, 10);
      }
    } catch {
      // skip
    }
  }
  return null;
};

// ─── Page ────────────────────────────────────────────────────────────────────

export const LogsPage: React.FC = () => {
  const [filters, setFilters] = useState<LogsFilterState>(defaultLogsFilters);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState<number>(0);
  const [pageSize, setPageSize] = useState<number>(100);
  const [rawMode, setRawMode] = useState(false);
  const [rawValue, setRawValue] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  const computedLogsQL = useMemo(() => filtersToLogsQL(filters), [filters]);

  // Refine `useList` calls our VictoriaLogs data provider via the resource's
  // `dataProviderName: "vlogs"` configured in App.tsx. The advanced/raw
  // mode swaps the structured filter array for a single `raw` filter so the
  // user's hand-written LogsQL goes through unchanged.
  const filterArray = useMemo(() => {
    if (rawMode && rawValue.trim()) {
      return [{ field: "raw", operator: "eq" as const, value: rawValue.trim() }];
    }
    return filtersToCrud(filters);
  }, [filters, rawMode, rawValue]);

  const {
    result,
    query,
  } = useList<LogRow>({
    resource: "logs",
    dataProviderName: "vlogs",
    filters: filterArray,
    pagination: { pageSize, mode: "off" },
    meta: { timeRange: filters.range },
    queryOptions: {
      staleTime: 0,
      refetchInterval: autoRefresh && refreshInterval > 0 ? refreshInterval : false,
    },
  });

  const stats = useLogsStats(refreshKey);
  const total24h = parseTotalFromStats(stats.count_24h_raw);

  // Decorate rows with stable keys (timestamp + req_id) so AntD doesn't fall
  // back to row-index keys (which break expansion across re-renders).
  const rows = useMemo(() => {
    const list = Array.isArray(result?.data) ? (result.data as LogRow[]) : [];
    return list.map((r, idx) => ({
      ...r,
      __rowKey: `${r._time ?? ""}-${r.req_id ?? ""}-${idx}`,
    }));
  }, [result?.data]);

  const handleRun = () => {
    setRefreshKey((k) => k + 1);
    void query.refetch();
  };

  const handleFilterClientIp = (ip: string) => {
    setFilters((s) => ({ ...s, clientIp: ip }));
    void message.info(`Filter set: client_ip = ${ip}`);
  };

  const handleFilterRuleName = (rule: string) => {
    setFilters((s) => ({ ...s, ruleName: rule }));
    void message.info(`Filter set: rule_name = ${rule}`);
  };

  // ── Empty state when the proxy reports VictoriaLogs disabled ─────────────
  const errorBody = query.error as { statusCode?: number; message?: string } | undefined;
  const showDisabledState =
    errorBody?.statusCode === 400 &&
    typeof errorBody.message === "string" &&
    errorBody.message.toLowerCase().includes("disabled");

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          Security Logs
        </Typography.Title>
        <Space>
          <Switch
            checkedChildren="Auto"
            unCheckedChildren="Manual"
            checked={autoRefresh}
            onChange={setAutoRefresh}
          />
          {autoRefresh && (
            <Space.Compact>
              <Button
                size="small"
                type={refreshInterval === 10_000 ? "primary" : "default"}
                onClick={() => setRefreshInterval(10_000)}
              >
                10s
              </Button>
              <Button
                size="small"
                type={refreshInterval === 30_000 ? "primary" : "default"}
                onClick={() => setRefreshInterval(30_000)}
              >
                30s
              </Button>
              <Button
                size="small"
                type={refreshInterval === 60_000 ? "primary" : "default"}
                onClick={() => setRefreshInterval(60_000)}
              >
                60s
              </Button>
            </Space.Compact>
          )}
          <Button icon={<ReloadOutlined spin={query.isFetching} />} onClick={handleRun}>
            Refresh
          </Button>
        </Space>
      </Space>

      {showDisabledState && (
        <Alert
          type="info"
          showIcon
          message="VictoriaLogs is disabled"
          description={
            <span>
              Set <code>[victoria_logs] enabled = true</code> in <code>configs/default.toml</code>{" "}
              and restart the WAF to enable the security log archive.
            </span>
          }
        />
      )}

      <Row gutter={12}>
        <Col span={6}>
          <Card size="small">
            <Statistic
              title="Entries (24h)"
              value={total24h ?? "—"}
              valueStyle={{ fontSize: 18 }}
            />
          </Card>
        </Col>
        <Col span={18}>
          <LogsQueryBar
            computed={computedLogsQL}
            rawMode={rawMode}
            rawValue={rawValue}
            onRawChange={setRawValue}
            onModeChange={(raw) => {
              setRawMode(raw);
              if (raw && !rawValue) setRawValue(computedLogsQL);
            }}
            onRun={handleRun}
            loading={query.isFetching}
          />
        </Col>
      </Row>

      <Row gutter={12}>
        <Col span={6}>
          <LogsFilters
            value={filters}
            onChange={setFilters}
            onApply={handleRun}
            loading={query.isFetching}
          />
        </Col>
        <Col span={18}>
          <Card size="small">
            <LogsTable
              rows={rows}
              loading={query.isFetching}
              pageSize={pageSize}
              setPageSize={setPageSize}
              onFilterClientIp={handleFilterClientIp}
              onFilterRuleName={handleFilterRuleName}
            />
          </Card>
        </Col>
      </Row>
    </Space>
  );
};
