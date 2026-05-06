import {
  DashboardOutlined,
  GlobalOutlined,
  SafetyOutlined,
  LinkOutlined,
  AlertOutlined,
  ContainerOutlined,
  FileTextOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  BellOutlined,
  SettingOutlined,
  ClusterOutlined,
  KeyOutlined,
  SyncOutlined,
  CloudOutlined,
  StopOutlined,
  BarChartOutlined,
  BookOutlined,
  BranchesOutlined,
  RobotOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import type { ComponentType } from "react";

export interface NavItem {
  key: string;
  i18nKey: string;
  path: string;
  icon: ComponentType;
  section?: string;
}

// Single source of truth for sidebar layout. Order = render order.
export const navItems: NavItem[] = [
  { key: "dashboard", i18nKey: "nav.dashboard", path: "/dashboard", icon: DashboardOutlined },
  { key: "hosts", i18nKey: "nav.hosts", path: "/hosts", icon: GlobalOutlined },
  { key: "ip-rules", i18nKey: "nav.ipRules", path: "/ip-rules", icon: SafetyOutlined },
  { key: "url-rules", i18nKey: "nav.urlRules", path: "/url-rules", icon: LinkOutlined },
  { key: "security-events", i18nKey: "nav.securityEvents", path: "/security-events", icon: AlertOutlined },
  { key: "logs", i18nKey: "nav.logs", path: "/logs", icon: ContainerOutlined },
  { key: "custom-rules", i18nKey: "nav.customRules", path: "/custom-rules", icon: FileTextOutlined },
  { key: "certificates", i18nKey: "nav.certificates", path: "/certificates", icon: LockOutlined },
  { key: "cc-protection", i18nKey: "nav.ccProtection", path: "/cc-protection", icon: SafetyCertificateOutlined },
  { key: "notifications", i18nKey: "nav.notifications", path: "/notifications", icon: BellOutlined },
  { key: "settings", i18nKey: "nav.settings", path: "/settings", icon: SettingOutlined },

  { key: "cluster", i18nKey: "nav.clusterOverview", path: "/cluster", icon: ClusterOutlined, section: "nav.cluster" },
  { key: "cluster-tokens", i18nKey: "nav.clusterTokens", path: "/cluster/tokens", icon: KeyOutlined, section: "nav.cluster" },
  { key: "cluster-sync", i18nKey: "nav.clusterSync", path: "/cluster/sync", icon: SyncOutlined, section: "nav.cluster" },

  { key: "crowdsec-settings", i18nKey: "nav.csSettings", path: "/crowdsec-settings", icon: CloudOutlined, section: "nav.crowdsec" },
  { key: "crowdsec-decisions", i18nKey: "nav.csDecisions", path: "/crowdsec-decisions", icon: StopOutlined, section: "nav.crowdsec" },
  { key: "crowdsec-stats", i18nKey: "nav.csStats", path: "/crowdsec-stats", icon: BarChartOutlined, section: "nav.crowdsec" },

  { key: "rules-management", i18nKey: "nav.ruleManager", path: "/rules-management", icon: BookOutlined, section: "nav.rules" },
  { key: "rule-sources", i18nKey: "nav.ruleSources", path: "/rule-sources", icon: BranchesOutlined, section: "nav.rules" },
  { key: "bot-management", i18nKey: "nav.botDetection", path: "/bot-management", icon: RobotOutlined, section: "nav.rules" },

  { key: "cache", i18nKey: "nav.cacheDashboard", path: "/cache", icon: ThunderboltOutlined, section: "nav.cache" },
];
