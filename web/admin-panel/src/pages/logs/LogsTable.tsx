import { useEffect, useMemo, useState } from "react";
import { Table, Typography } from "antd";
import type { ColumnType, ColumnsType } from "antd/es/table";
import {
  DndContext,
  type DragEndEvent,
  PointerSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import { restrictToHorizontalAxis } from "@dnd-kit/modifiers";
import {
  SortableContext,
  arrayMove,
  horizontalListSortingStrategy,
  useSortable,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

import { LogsColumnsPicker } from "./LogsColumnsPicker";
import { buildBuiltinColumns, renderGenericCell } from "./LogsColumns";

// Each row is a free-form JSON object (NDJSON line from VictoriaLogs). We
// type the well-known shape but tolerate extra fields in the expand row.
export interface LogRow {
  _time?: string;
  _msg?: string;
  event_type?: string;
  rule_name?: string;
  rule_id?: string | null;
  client_ip?: string;
  host?: string;
  method?: string;
  path?: string;
  tier?: string;
  detail?: string;
  req_id?: string;
  // Used by AntD as the row key — derived in the page so this is just
  // a passthrough field carried forwards from the unique tuple
  // (timestamp + req_id) when present.
  __rowKey?: string;
  // Tracing-stream rows include `level`, `target`, `stream`, etc. Expand
  // row simply pretty-prints the whole object so they're still readable.
  [extra: string]: unknown;
}

/** localStorage key for persisted column state. Bump suffix on schema break. */
const LS_KEY = "prx-waf:logs:columns:v1";

interface PersistedShape {
  visible?: unknown;
  custom?: unknown;
}

interface Props {
  rows: LogRow[];
  loading: boolean;
  pageSize: number;
  setPageSize: (n: number) => void;
  /** Click → set client_ip filter to this value upstream. */
  onFilterClientIp: (ip: string) => void;
  /** Click → set rule_name filter to this value upstream. */
  onFilterRuleName: (rule: string) => void;
}

export const LogsTable: React.FC<Props> = ({
  rows,
  loading,
  pageSize,
  setPageSize,
  onFilterClientIp,
  onFilterRuleName,
}) => {
  const builtins = useMemo(
    () => buildBuiltinColumns(onFilterClientIp, onFilterRuleName),
    [onFilterClientIp, onFilterRuleName],
  );
  const builtinIds = useMemo(() => builtins.map((c) => c.id), [builtins]);
  const builtinLabels = useMemo(
    () => Object.fromEntries(builtins.map((c) => [c.id, c.label])),
    [builtins],
  );

  // Persisted state — survives reloads via localStorage.
  const [visible, setVisible] = useState<string[]>(() => loadVisible(builtinIds));
  const [customIds, setCustomIds] = useState<string[]>(() => loadCustom());

  useEffect(() => {
    try {
      localStorage.setItem(LS_KEY, JSON.stringify({ visible, custom: customIds }));
    } catch {
      // localStorage may be unavailable / full / blocked — non-fatal.
    }
  }, [visible, customIds]);

  // Discover field names from the *current* page of rows. Excludes anything
  // already pinned and any internal `__*` key (e.g. `__rowKey`).
  const discoveredIds = useMemo(() => {
    const known = new Set([...builtinIds, ...customIds]);
    const set = new Set<string>();
    for (const r of rows) {
      for (const key of Object.keys(r)) {
        if (key.startsWith("__")) continue;
        if (known.has(key)) continue;
        set.add(key);
      }
    }
    return Array.from(set).sort();
  }, [rows, builtinIds, customIds]);

  const handlePickerChange = (nextVisible: string[], nextCustom: string[]) => {
    setVisible(nextVisible);
    setCustomIds(nextCustom);
  };

  const handleReset = () => {
    setVisible(builtinIds);
    setCustomIds([]);
  };

  // Build the AntD columns array from `visible`. Built-in ids → use the
  // pre-defined renderer. Anything else → render generically. Each column
  // also carries `onHeaderCell` so DnD can pick up its drag id.
  const columns: ColumnsType<LogRow> = useMemo(() => {
    return visible.map((id): ColumnType<LogRow> => {
      const base: ColumnType<LogRow> = (() => {
        const builtin = builtins.find((c) => c.id === id);
        if (builtin) return { ...builtin.def, key: id };
        return {
          title: <code style={{ fontSize: 12 }}>{id}</code>,
          dataIndex: id,
          key: id,
          width: 180,
          ellipsis: true,
          render: renderGenericCell,
        };
      })();
      return { ...base, onHeaderCell: () => ({ id } as React.HTMLAttributes<HTMLElement>) };
    });
  }, [visible, builtins]);

  // ── Drag-and-drop reordering ──────────────────────────────────────────
  // PointerSensor with a small activation distance prevents accidental
  // drags on click — important because we want regular clicks on the
  // header row (e.g. AntD's column-resize handle in future) to keep working.
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }));

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    setVisible((prev) => {
      const fromIdx = prev.indexOf(String(active.id));
      const toIdx = prev.indexOf(String(over.id));
      if (fromIdx < 0 || toIdx < 0) return prev;
      return arrayMove(prev, fromIdx, toIdx);
    });
  };

  return (
    <DndContext
      sensors={sensors}
      modifiers={[restrictToHorizontalAxis]}
      onDragEnd={handleDragEnd}
    >
      <SortableContext items={visible} strategy={horizontalListSortingStrategy}>
        <Table<LogRow>
          rowKey="__rowKey"
          size="small"
          dataSource={rows}
          columns={columns}
          loading={loading}
          components={{ header: { cell: SortableHeaderCell } }}
          title={() => (
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ color: "#8c8c8c", fontSize: 12 }}>
                {rows.length === 0 ? "No entries" : `${rows.length} entries`}
                <span style={{ marginLeft: 12, color: "#bfbfbf" }}>
                  Drag a column header to reorder
                </span>
              </span>
              <LogsColumnsPicker
                builtinIds={builtinIds}
                builtinLabels={builtinLabels}
                customIds={customIds}
                discoveredIds={discoveredIds}
                visible={visible}
                onChange={handlePickerChange}
                onReset={handleReset}
              />
            </div>
          )}
          pagination={{
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: [50, 100, 500],
            onShowSizeChange: (_c, ps) => setPageSize(ps),
            showTotal: (n) => `Total: ${n}`,
          }}
          expandable={{
            expandedRowRender: (row) => (
              <Typography.Paragraph style={{ marginBottom: 0 }}>
                <pre
                  style={{
                    fontSize: 12,
                    margin: 0,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {JSON.stringify(row, null, 2)}
                </pre>
              </Typography.Paragraph>
            ),
          }}
          scroll={{ x: 1200 }}
          locale={{ emptyText: "No log entries match your filters" }}
        />
      </SortableContext>
    </DndContext>
  );
};

// ── Sortable header cell ────────────────────────────────────────────────────

/**
 * Replacement `<th>` registered via `Table.components.header.cell`.
 *
 * AntD calls this with the props returned from each column's
 * `onHeaderCell`, so `id` is the column key. When `id` is missing
 * (e.g. AntD's selection / expand columns) we render a plain `<th>`
 * to stay out of the DnD context.
 */
type SortableHeaderProps = React.HTMLAttributes<HTMLTableCellElement> & { id?: string };

const SortableHeaderCell: React.FC<SortableHeaderProps> = ({ id, style, ...rest }) => {
  // Hooks MUST run unconditionally — we always call `useSortable`, but
  // pass an unreachable id when there's no column key so the slot stays
  // inert and AntD's auxiliary header cells render normally.
  const sortable = useSortable({ id: id ?? "__antd_static_header__" });
  if (!id) return <th style={style} {...rest} />;

  const dragStyle: React.CSSProperties = {
    ...style,
    cursor: sortable.isDragging ? "grabbing" : "grab",
    transform: CSS.Translate.toString(sortable.transform),
    transition: sortable.transition,
    ...(sortable.isDragging
      ? { position: "relative", zIndex: 9999, background: "#f0f5ff" }
      : {}),
    userSelect: "none",
  };
  return (
    <th
      {...rest}
      ref={sortable.setNodeRef}
      style={dragStyle}
      {...sortable.attributes}
      {...sortable.listeners}
    />
  );
};

// ── localStorage hydration helpers ──────────────────────────────────────────

const loadVisible = (defaults: string[]): string[] => {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw) as PersistedShape;
    if (Array.isArray(parsed.visible) && parsed.visible.every((s) => typeof s === "string")) {
      return parsed.visible as string[];
    }
  } catch {
    // fall through to defaults
  }
  return defaults;
};

const loadCustom = (): string[] => {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as PersistedShape;
    if (Array.isArray(parsed.custom) && parsed.custom.every((s) => typeof s === "string")) {
      return parsed.custom as string[];
    }
  } catch {
    // fall through to empty
  }
  return [];
};
