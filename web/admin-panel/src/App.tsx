import { Refine, Authenticated } from "@refinedev/core";
import { RefineKbarProvider } from "@refinedev/kbar";
import { ErrorComponent, useNotificationProvider } from "@refinedev/antd";
import "@refinedev/antd/dist/reset.css";
import routerProvider, {
  CatchAllNavigate,
  NavigateToResource,
} from "@refinedev/react-router";
import { HashRouter, Outlet, Route, Routes } from "react-router-dom";
import { ConfigProvider, App as AntdApp } from "antd";

import { dataProvider } from "./providers/data-provider";
import { victoriaLogsDataProvider } from "./providers/victoria-logs-data-provider";
import { authProvider } from "./providers/auth-provider";
import { i18nProvider } from "./providers/i18n-provider";
import { liveProvider } from "./providers/live-provider";
import { useAppTheme } from "./hooks/use-app-theme";
import { useQueryClient } from "./hooks/use-query-client";
import { AppLayout } from "./layouts/app-layout";
import { ErrorBoundary } from "./components/error-boundary";
import { AdminOnly } from "./components/admin-only";

import { LoginPage } from "./pages/login";
import { DashboardPage } from "./pages/dashboard";
import { LogsPage } from "./pages/logs";
import { HostsPage } from "./pages/hosts";
import { IpRulesPage } from "./pages/ip-rules";
import { UrlRulesPage } from "./pages/url-rules";
import { CustomRulesPage } from "./pages/custom-rules";
import { CertificatesPage } from "./pages/certificates";
import { SecurityEventsPage } from "./pages/security-events";
import { CcProtectionPage } from "./pages/cc-protection";
import { NotificationsPage } from "./pages/notifications";
import { SettingsPage } from "./pages/settings";
import { CrowdsecSettingsPage } from "./pages/crowdsec-settings";
import { CrowdsecDecisionsPage } from "./pages/crowdsec-decisions";
import { CrowdsecStatsPage } from "./pages/crowdsec-stats";
import { RulesManagementPage } from "./pages/rules-management";
import { RuleSourcesPage } from "./pages/rule-sources";
import { BotManagementPage } from "./pages/bot-management";
import { ClusterOverviewPage } from "./pages/cluster/overview";
import { ClusterNodeDetailPage } from "./pages/cluster/node-detail";
import { ClusterTokensPage } from "./pages/cluster/tokens";
import { ClusterSyncPage } from "./pages/cluster/sync";
import { CacheDashboardPage } from "./pages/cache";

// Each Refine `resource` is what binds list/create/edit/delete pages,
// the data provider, and the navigation system. Path on resource is what
// shows up in router; here we use kebab-case slugs that match the legacy URLs.
const resources = [
  { name: "dashboard", list: "/dashboard" },
  { name: "hosts", list: "/hosts" },
  { name: "ip-rules", list: "/ip-rules" },
  { name: "url-rules", list: "/url-rules" },
  { name: "security-events", list: "/security-events" },
  { name: "logs", list: "/logs", meta: { dataProviderName: "vlogs" } },
  { name: "custom-rules", list: "/custom-rules" },
  { name: "certificates", list: "/certificates" },
  { name: "cc-protection", list: "/cc-protection" },
  { name: "notifications", list: "/notifications" },
  { name: "settings", list: "/settings" },
  { name: "crowdsec-settings", list: "/crowdsec-settings" },
  { name: "crowdsec-decisions", list: "/crowdsec-decisions" },
  { name: "crowdsec-stats", list: "/crowdsec-stats" },
  { name: "rules-management", list: "/rules-management" },
  { name: "rule-sources", list: "/rule-sources" },
  { name: "bot-management", list: "/bot-management" },
  { name: "cluster", list: "/cluster" },
  { name: "cluster-tokens", list: "/cluster/tokens" },
  { name: "cluster-sync", list: "/cluster/sync" },
  { name: "cache", list: "/cache" },
];

export const App: React.FC = () => {
  const themeConfig = useAppTheme();
  const queryClient = useQueryClient();

  return (
    <HashRouter>
      <ConfigProvider theme={themeConfig}>
        <AntdApp>
         <ErrorBoundary>
          <RefineKbarProvider>
            <Refine
              dataProvider={{
                default: dataProvider,
                vlogs: victoriaLogsDataProvider,
              }}
              authProvider={authProvider}
              i18nProvider={i18nProvider}
              liveProvider={liveProvider}
              routerProvider={routerProvider}
              notificationProvider={useNotificationProvider()}
              resources={resources}
              options={{
                syncWithLocation: true,
                warnWhenUnsavedChanges: true,
                liveMode: "off",
                reactQuery: { clientConfig: queryClient },
                disableTelemetry: true,
              }}
            >
              <Routes>
                <Route
                  element={
                    <Authenticated key="auth-inner" fallback={<CatchAllNavigate to="/login" />}>
                      <AppLayout>
                        <Outlet />
                      </AppLayout>
                    </Authenticated>
                  }
                >
                  <Route index element={<NavigateToResource resource="dashboard" />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/hosts" element={<HostsPage />} />
                  <Route path="/ip-rules" element={<IpRulesPage />} />
                  <Route path="/url-rules" element={<UrlRulesPage />} />
                  <Route path="/security-events" element={<SecurityEventsPage />} />
                  <Route path="/logs" element={<AdminOnly><LogsPage /></AdminOnly>} />
                  <Route path="/custom-rules" element={<CustomRulesPage />} />
                  <Route path="/certificates" element={<CertificatesPage />} />
                  <Route path="/cc-protection" element={<CcProtectionPage />} />
                  <Route path="/notifications" element={<NotificationsPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/crowdsec-settings" element={<CrowdsecSettingsPage />} />
                  <Route path="/crowdsec-decisions" element={<CrowdsecDecisionsPage />} />
                  <Route path="/crowdsec-stats" element={<CrowdsecStatsPage />} />
                  <Route path="/rules-management" element={<RulesManagementPage />} />
                  <Route path="/rule-sources" element={<RuleSourcesPage />} />
                  <Route path="/bot-management" element={<BotManagementPage />} />
                  <Route path="/cluster" element={<ClusterOverviewPage />} />
                  <Route path="/cluster/nodes/:id" element={<ClusterNodeDetailPage />} />
                  <Route path="/cluster/tokens" element={<ClusterTokensPage />} />
                  <Route path="/cluster/sync" element={<ClusterSyncPage />} />
                  <Route path="/cache" element={<CacheDashboardPage />} />
                  <Route path="*" element={<ErrorComponent />} />
                </Route>

                <Route
                  element={
                    <Authenticated key="auth-outer" fallback={<Outlet />}>
                      <NavigateToResource resource="dashboard" />
                    </Authenticated>
                  }
                >
                  <Route path="/login" element={<LoginPage />} />
                </Route>
              </Routes>
            </Refine>
          </RefineKbarProvider>
         </ErrorBoundary>
        </AntdApp>
      </ConfigProvider>
    </HashRouter>
  );
};

