import { useMemo, useState } from "react";
import { Button, Checkbox, Divider, Input, Popover, Space, Tooltip, Typography } from "antd";
import { PlusOutlined, SettingOutlined } from "@ant-design/icons";

interface Props {
  /** Ordered list of built-in column ids (canonical order). */
  builtinIds: string[];
  /** Display labels for built-in ids (id → label). */
  builtinLabels: Record<string, string>;
  /** User-saved custom field names. Persist across reloads. */
  customIds: string[];
  /** Field names seen in the current rows but not built-in or already-custom. */
  discoveredIds: string[];
  /** Currently visible column ids (ordered). */
  visible: string[];
  /** Notify parent of a new (visible, custom) tuple. */
  onChange: (visible: string[], custom: string[]) => void;
  /** Restore the original built-in defaults; clears all custom additions. */
  onReset: () => void;
}

/**
 * Column-visibility picker for the Security Logs table.
 *
 * The popover lists three sources of columns:
 *   1. Built-in (always visible in the picker, on/off togglable).
 *   2. Custom — user-added field names that persist across reloads.
 *   3. Discovered — fields seen in the *current* page of rows but not yet
 *      promoted; toggling one ON also pins it to the custom list.
 *
 * The free-text "Add" input lets the user pin a field name that doesn't
 * appear in the current rows yet (handy for filtering by `target`,
 * `req_id`, `_stream_id`, etc. before any matching log shows up).
 */
export const LogsColumnsPicker: React.FC<Props> = ({
  builtinIds,
  builtinLabels,
  customIds,
  discoveredIds,
  visible,
  onChange,
  onReset,
}) => {
  const [newField, setNewField] = useState("");
  const visibleSet = useMemo(() => new Set(visible), [visible]);

  const setChecked = (id: string, checked: boolean, pinAsCustom = false) => {
    let nextVisible = visible;
    let nextCustom = customIds;
    if (checked) {
      if (!visibleSet.has(id)) nextVisible = [...visible, id];
      if (pinAsCustom && !builtinIds.includes(id) && !customIds.includes(id)) {
        nextCustom = [...customIds, id];
      }
    } else {
      nextVisible = visible.filter((v) => v !== id);
    }
    onChange(nextVisible, nextCustom);
  };

  const addNewField = () => {
    const id = newField.trim();
    if (!id || id.startsWith("__")) {
      // Reject empty + double-underscore (those are internal keys like __rowKey).
      setNewField("");
      return;
    }
    const isBuiltin = builtinIds.includes(id);
    const nextVisible = visibleSet.has(id) ? visible : [...visible, id];
    const nextCustom = isBuiltin || customIds.includes(id) ? customIds : [...customIds, id];
    onChange(nextVisible, nextCustom);
    setNewField("");
  };

  const removeCustom = (id: string) => {
    onChange(
      visible.filter((v) => v !== id),
      customIds.filter((c) => c !== id),
    );
  };

  const content = (
    <div style={{ minWidth: 280, maxWidth: 380, maxHeight: 480, overflowY: "auto" }}>
      <Typography.Text strong>Columns</Typography.Text>
      <Divider style={{ margin: "8px 0" }} />

      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        Built-in
      </Typography.Text>
      <div style={{ marginTop: 4, marginBottom: 4 }}>
        {builtinIds.map((id) => (
          <div key={id}>
            <Checkbox
              checked={visibleSet.has(id)}
              onChange={(e) => setChecked(id, e.target.checked)}
            >
              {builtinLabels[id] ?? id}
            </Checkbox>
          </div>
        ))}
      </div>

      {customIds.length > 0 && (
        <>
          <Divider style={{ margin: "8px 0" }} />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            Custom (saved)
          </Typography.Text>
          <div style={{ marginTop: 4 }}>
            {customIds.map((id) => (
              <div
                key={id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <Checkbox
                  checked={visibleSet.has(id)}
                  onChange={(e) => setChecked(id, e.target.checked, true)}
                >
                  <code style={{ fontSize: 12 }}>{id}</code>
                </Checkbox>
                <Button
                  size="small"
                  type="text"
                  danger
                  onClick={() => removeCustom(id)}
                  title="Remove from saved list"
                >
                  ×
                </Button>
              </div>
            ))}
          </div>
        </>
      )}

      {discoveredIds.length > 0 && (
        <>
          <Divider style={{ margin: "8px 0" }} />
          <Tooltip title="Fields seen in the current rows but not pinned yet. Checking pins them.">
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              Discovered in current rows
            </Typography.Text>
          </Tooltip>
          <div style={{ marginTop: 4 }}>
            {discoveredIds.map((id) => (
              <div key={id}>
                <Checkbox
                  checked={visibleSet.has(id)}
                  onChange={(e) => setChecked(id, e.target.checked, true)}
                >
                  <code style={{ fontSize: 12 }}>{id}</code>
                </Checkbox>
              </div>
            ))}
          </div>
        </>
      )}

      <Divider style={{ margin: "8px 0" }} />
      <Space.Compact style={{ width: "100%" }}>
        <Input
          placeholder="Add field name (e.g. target, _stream_id)"
          value={newField}
          onChange={(e) => setNewField(e.target.value)}
          onPressEnter={addNewField}
          size="small"
        />
        <Button size="small" type="primary" icon={<PlusOutlined />} onClick={addNewField}>
          Add
        </Button>
      </Space.Compact>

      <Divider style={{ margin: "8px 0" }} />
      <Button type="link" size="small" onClick={onReset} style={{ padding: 0 }}>
        Reset to defaults
      </Button>
    </div>
  );

  return (
    <Popover content={content} trigger="click" placement="bottomRight">
      <Button size="small" icon={<SettingOutlined />}>
        Columns ({visible.length})
      </Button>
    </Popover>
  );
};
