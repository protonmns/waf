import {
  Row, Col, Card, Statistic, Button, Typography, Space, Table,
  Progress, Tag, Input, Modal, message, Divider,
} from "antd";
import {
  ReloadOutlined, ThunderboltOutlined, DatabaseOutlined,
  HddOutlined, PercentageOutlined, DeleteOutlined, ClearOutlined,
  TagsOutlined,
} from "@ant-design/icons";
import { useCustom, useApiUrl } from "@refinedev/core";
import { useTranslation } from "react-i18next";
import { Line } from "@ant-design/plots";
import { useMemo, useState } from "react";
import dayjs from "dayjs";
import { httpClient } from "../../utils/axios";

const { Title, Text } = Typography;

// ── API types ─────────────────────────────────────────────────────────────────

interface CacheStats {
  hit_ratio?: number;
  entry_count?: number;
  hits?: number;
  misses?: number;
  stores?: number;
  evictions?: number;
  memory_used_bytes?: number;
  backend?: string;
  valkey_ops_per_sec?: number;
  tag_index_size?: number;
}

interface BackendInfo {
  backend?: string;
  valkey_version?: string;
  connected?: boolean;
  circuit_breaker?: string;
  memory_used_bytes?: number;
  memory_max_bytes?: number;
  nodes?: { addr: string; role: string; slots: string }[];
}

interface TsBucket {
  ts: string;
  hits: number;
  misses: number;
  hit_ratio: number;
}

interface RouteRow {
  route_id: string;
  hits: number;
  entry_count: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtBytes(n?: number): string {
  if (!n) return "—";
  if (n >= 1_073_741_824) return `${(n / 1_073_741_824).toFixed(1)} GB`;
  if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function fmtNum(n?: number): string {
  if (n === undefined || n === null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

function circuitColor(cb?: string): string {
  if (cb === "closed") return "success";
  if (cb === "half_open") return "warning";
  if (cb === "open") return "error";
  return "default";
}

/** Normalize Refine `useCustom` payloads across data-provider / version differences. */
function refineCustomData<T>(h: {
  data?: T;
  result?: { data?: T };
}): T | undefined {
  return h.data ?? h.result?.data;
}

function refineCustomRefetch(h: {
  query?: { refetch?: () => unknown };
  refetch?: () => void;
}): void {
  void h.query?.refetch?.();
  void h.refetch?.();
}

function refineCustomLoading(h: {
  isLoading?: boolean;
  query?: { isLoading?: boolean; isFetching?: boolean };
}): { isLoading: boolean; isFetching: boolean } {
  return {
    isLoading: h.isLoading ?? h.query?.isLoading ?? false,
    isFetching: h.query?.isFetching ?? false,
  };
}

// ── Page ──────────────────────────────────────────────────────────────────────

export const CacheDashboardPage: React.FC = () => {
  const { t } = useTranslation();
  const apiUrl = useApiUrl();
  const [purgeTagVal, setPurgeTagVal] = useState("");
  const [purgeRouteVal, setPurgeRouteVal] = useState("");
  const [flushModal, setFlushModal] = useState(false);
  const [acting, setActing] = useState(false);
  // ── Data fetching (each at its own interval) ───────────────────────────────

  const statsQ = useCustom<CacheStats>({
    url: `${apiUrl}/cache/stats`,
    method: "get",
    queryOptions: { staleTime: 4_000, refetchInterval: 5_000 },
  });

  const backendQ = useCustom<BackendInfo>({
    url: `${apiUrl}/cache/backend`,
    method: "get",
    queryOptions: { staleTime: 14_000, refetchInterval: 15_000 },
  });

  const tsQ = useCustom<TsBucket[]>({
    url: `${apiUrl}/cache/stats/timeseries`,
    method: "get",
    config: { query: { minutes: 60 } },
    queryOptions: { staleTime: 59_000, refetchInterval: 60_000 },
  });

  const routesQ = useCustom<RouteRow[]>({
    url: `${apiUrl}/cache/routes/top`,
    method: "get",
    config: { query: { limit: 20 } },
    queryOptions: { staleTime: 29_000, refetchInterval: 30_000 },
  });

  const stats = refineCustomData(statsQ);
  const backend = refineCustomData(backendQ);
  const rawTs = refineCustomData(tsQ);
  const routesRaw = refineCustomData(routesQ);
  // Defensive: useCustom can return an envelope object instead of a plain array
  // if the data-provider wrapping changes; Array.isArray guards against that.
  const routes = Array.isArray(routesRaw) ? routesRaw : [];

  // Flatten timeseries into long-form for @ant-design/plots Line.
  // `Number(...) || 0` matches TrafficChart's pattern — guards against null/NaN
  // that would cause @ant-design/plots to crash in its internal useMemo.
  const tsData = useMemo(() => {
    const arr = Array.isArray(rawTs) ? rawTs : [];
    const out: { ts: string; value: number; series: string }[] = [];
    for (const b of arr) {
      const label = dayjs(b.ts).format("HH:mm");
      out.push({ ts: label, value: Number(b.hits) || 0, series: t("cache.hits") });
      out.push({ ts: label, value: Number(b.misses) || 0, series: t("cache.misses") });
    }
    return out;
  }, [rawTs, t]);

  const memPct = useMemo(() => {
    if (!backend?.memory_used_bytes || !backend?.memory_max_bytes) return null;
    return Math.min(100, (backend.memory_used_bytes / backend.memory_max_bytes) * 100);
  }, [backend]);

  /** In-process Moka has no Valkey `INFO`; show tag-index depth instead of ops/sec. */
  const fourthKpiIsTagIndex = stats?.backend === "memory";

  const { isLoading, isFetching } = refineCustomLoading(statsQ);

  function refetchAll() {
    refineCustomRefetch(statsQ);
    refineCustomRefetch(backendQ);
    refineCustomRefetch(tsQ);
    refineCustomRefetch(routesQ);
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  async function doPurgeTag() {
    const tag = purgeTagVal.trim();
    if (!tag) return;
    setActing(true);
    try {
      const r = await httpClient.post("/api/cache/purge/tag", { tag });
      message.success(t("cache.purged", { n: r.data?.purged ?? 0 }));
      setPurgeTagVal("");
      refineCustomRefetch(statsQ);
    } catch {
      message.error(t("cache.purgeError"));
    } finally {
      setActing(false);
    }
  }

  async function doPurgeRoute(routeId: string) {
    setActing(true);
    try {
      const r = await httpClient.post("/api/cache/purge/route", { route_id: routeId });
      message.success(t("cache.purged", { n: r.data?.purged ?? 0 }));
      refineCustomRefetch(statsQ);
      refineCustomRefetch(routesQ);
    } catch {
      message.error(t("cache.purgeError"));
    } finally {
      setActing(false);
    }
  }

  async function doPurgeRouteInput() {
    const route = purgeRouteVal.trim();
    if (!route) return;
    await doPurgeRoute(route);
    setPurgeRouteVal("");
  }

  async function doFlush() {
    setFlushModal(false);
    setActing(true);
    try {
      await httpClient.delete("/api/cache");
      message.success(t("cache.flushed"));
      refetchAll();
    } catch {
      message.error(t("cache.purgeError"));
    } finally {
      setActing(false);
    }
  }

  // ── Route columns ─────────────────────────────────────────────────────────

  const routeColumns = [
    {
      title: "Route",
      dataIndex: "route_id",
      key: "route_id",
      render: (v: string) => <Text code style={{ fontSize: 12 }}>{v}</Text>,
    },
    {
      title: t("cache.hits"),
      dataIndex: "hits",
      key: "hits",
      align: "right" as const,
      render: (v: number) => fmtNum(v),
    },
    {
      title: t("cache.entries"),
      dataIndex: "entry_count",
      key: "entry_count",
      align: "right" as const,
      render: (v: number) => fmtNum(v),
    },
    {
      title: "",
      key: "action",
      align: "right" as const,
      render: (_: unknown, row: RouteRow) => (
        <Button
          size="small"
          danger
          icon={<DeleteOutlined />}
          loading={acting}
          onClick={() => doPurgeRoute(row.route_id)}
        >
          {t("cache.purgeRoute")}
        </Button>
      ),
    },
  ];

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {/* Header */}
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <div>
          <Title level={4} style={{ margin: 0 }}>{t("cache.title")}</Title>
          <Text type="secondary" style={{ fontSize: 12 }}>{t("cache.subtitle")}</Text>
        </div>
        <Button
          icon={<ReloadOutlined spin={isFetching} />}
          onClick={refetchAll}
          loading={isLoading}
          type="primary"
        >
          {t("common.refresh")}
        </Button>
      </Space>

      {/* KPI row */}
      <Row gutter={[16, 16]}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("cache.hitRatio")}
              value={stats?.hit_ratio != null ? (stats.hit_ratio * 100).toFixed(1) : "—"}
              suffix={stats?.hit_ratio != null ? "%" : ""}
              prefix={<PercentageOutlined />}
              valueStyle={{ color: "#52c41a" }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("cache.entries")}
              value={stats?.entry_count != null ? fmtNum(stats.entry_count) : "—"}
              prefix={<DatabaseOutlined />}
              valueStyle={{ color: "#1677ff" }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={t("cache.memoryUsed")}
              value={fmtBytes(stats?.memory_used_bytes)}
              prefix={<HddOutlined />}
              valueStyle={{ color: "#722ed1" }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title={fourthKpiIsTagIndex ? t("cache.tagIndex") : t("cache.opsPerSec")}
              value={
                fourthKpiIsTagIndex
                  ? (stats?.tag_index_size != null ? fmtNum(stats.tag_index_size) : "—")
                  : (stats?.valkey_ops_per_sec != null ? fmtNum(stats.valkey_ops_per_sec) : "—")
              }
              prefix={fourthKpiIsTagIndex ? <TagsOutlined /> : <ThunderboltOutlined />}
              valueStyle={{ color: fourthKpiIsTagIndex ? "#13c2c2" : "#fa8c16" }}
            />
          </Card>
        </Col>
      </Row>

      {/* Hit / Miss timeline chart */}
      <Card title={t("cache.hitMissTimeline")}>
        {tsData.length > 0 ? (
          <Line
            data={tsData}
            xField="ts"
            yField="value"
            seriesField="series"
            height={220}
            smooth
            animate={false}
            color={["#52c41a", "#f5222d"]}
            point={{ size: 2 }}
            xAxis={{ tickCount: 6 }}
          />
        ) : (
          <div style={{ height: 220, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Text type="secondary">{t("common.noData")}</Text>
          </div>
        )}
      </Card>

      <Row gutter={[16, 16]}>
        {/* Top routes table */}
        <Col xs={24} lg={14}>
          <Card title={t("cache.topRoutes")}>
            <Table
              dataSource={routes}
              columns={routeColumns}
              rowKey="route_id"
              size="small"
              pagination={false}
              locale={{ emptyText: t("common.noData") }}
            />
          </Card>
        </Col>

        {/* Backend info */}
        <Col xs={24} lg={10}>
          <Card title={t("cache.backendInfo")}>
            <Space direction="vertical" size={12} style={{ width: "100%" }}>
              <Row gutter={8}>
                <Col span={12}>
                  <Text type="secondary">{t("cache.mode")}</Text>
                  <br />
                  <Text strong style={{ textTransform: "capitalize" }}>{backend?.backend ?? "—"}</Text>
                </Col>
                <Col span={12}>
                  <Text type="secondary">{t("cache.version")}</Text>
                  <br />
                  <Text code>{backend?.valkey_version ?? "—"}</Text>
                </Col>
              </Row>

              <Row gutter={8}>
                <Col span={12}>
                  <Text type="secondary">{t("cache.circuitBreaker")}</Text>
                  <br />
                  <Tag color={circuitColor(backend?.circuit_breaker)}>
                    {backend?.circuit_breaker ?? "—"}
                  </Tag>
                </Col>
                <Col span={12}>
                  <Text type="secondary">{t("cache.connected")}</Text>
                  <br />
                  <Tag color={backend?.connected ? "success" : "error"}>
                    {backend?.connected ? "✓" : "✗"}
                  </Tag>
                </Col>
              </Row>

              {/* Memory progress bar */}
              {memPct !== null && (
                <div>
                  <Text type="secondary">{t("cache.memoryUsed")}</Text>
                  <br />
                  <Text style={{ fontSize: 12 }}>
                    {fmtBytes(backend?.memory_used_bytes)} / {fmtBytes(backend?.memory_max_bytes)}
                  </Text>
                  <Progress
                    percent={parseFloat(memPct.toFixed(1))}
                    size="small"
                    status={memPct > 80 ? "exception" : memPct > 60 ? "active" : "normal"}
                    style={{ marginTop: 4 }}
                  />
                </div>
              )}

              {/* Cluster nodes table */}
              {backend?.nodes && backend.nodes.length > 0 && (
                <>
                  <Divider style={{ margin: "8px 0" }} />
                  <Text type="secondary">{t("cache.nodes")}</Text>
                  <Table
                    dataSource={backend.nodes}
                    rowKey="addr"
                    size="small"
                    pagination={false}
                    columns={[
                      { title: t("cache.nodes"), dataIndex: "addr", render: (v: string) => <Text code style={{ fontSize: 11 }}>{v}</Text> },
                      { title: t("cache.role"), dataIndex: "role", render: (v: string) => <Tag>{v}</Tag> },
                      { title: t("cache.slots"), dataIndex: "slots" },
                    ]}
                  />
                </>
              )}
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Actions bar */}
      <Card title={t("cache.actions")}>
        <Space wrap size={12}>
          <Space.Compact>
            <Input
              value={purgeTagVal}
              onChange={e => setPurgeTagVal(e.target.value)}
              placeholder={t("cache.purgeTag")}
              style={{ width: 180 }}
              onPressEnter={doPurgeTag}
            />
            <Button
              onClick={doPurgeTag}
              disabled={!purgeTagVal.trim()}
              loading={acting}
            >
              {t("cache.purgeTag")}
            </Button>
          </Space.Compact>

          <Space.Compact>
            <Input
              value={purgeRouteVal}
              onChange={e => setPurgeRouteVal(e.target.value)}
              placeholder={t("cache.purgeRoute")}
              style={{ width: 180 }}
              onPressEnter={doPurgeRouteInput}
            />
            <Button
              onClick={doPurgeRouteInput}
              disabled={!purgeRouteVal.trim()}
              loading={acting}
            >
              {t("cache.purgeRoute")}
            </Button>
          </Space.Compact>

          <Button
            danger
            icon={<ClearOutlined />}
            onClick={() => setFlushModal(true)}
            loading={acting}
          >
            {t("cache.flushAll")}
          </Button>
        </Space>
      </Card>

      {/* Flush confirm modal */}
      <Modal
        title={t("cache.flushAll")}
        open={flushModal}
        onOk={doFlush}
        onCancel={() => setFlushModal(false)}
        okText={t("cache.flushAll")}
        okButtonProps={{ danger: true }}
      >
        <Text>{t("cache.confirmFlush")}</Text>
      </Modal>
    </Space>
  );
};
