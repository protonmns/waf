import { useGetIdentity } from "@refinedev/core";
import { Result, Spin } from "antd";
import { Navigate } from "react-router-dom";

interface Identity {
  id?: string;
  name?: string;
  role?: string;
}

/**
 * Route-level guard restricting access to users whose JWT carries
 * `role: "admin"`. Non-admins are redirected to the dashboard, which is
 * the standard fallback for "no permission" elsewhere in the panel.
 *
 * This is a pure FE guard for UX clarity — the backend already rejects
 * non-admin tokens at the `/api/v1/logs/*` endpoints with 401.
 */
export const AdminOnly: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { data: identity, isLoading } = useGetIdentity<Identity>();

  if (isLoading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
        <Spin />
      </div>
    );
  }

  if (!identity?.role) {
    return <Navigate to="/login" replace />;
  }

  if (identity.role !== "admin") {
    return (
      <Result
        status="403"
        title="403"
        subTitle="This page requires the admin role."
      />
    );
  }

  return <>{children}</>;
};
