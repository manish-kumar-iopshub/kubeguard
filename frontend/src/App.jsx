import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import UnhealthyPods from "./pages/UnhealthyPods";
import SecretLeakage from "./pages/SecretLeakage";
import DeploymentRisk from "./pages/DeploymentRisk";
import DeploymentDetail from "./pages/DeploymentDetail";
import ScannerSettings from "./pages/ScannerSettings";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/unhealthy-pods" element={<UnhealthyPods />} />
        <Route path="/secret-leakage" element={<SecretLeakage />} />
        <Route path="/deployment-risk" element={<DeploymentRisk />} />
        <Route
          path="/deployment-risk/:namespace/:deployment"
          element={<DeploymentDetail />}
        />
        <Route path="/settings" element={<ScannerSettings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
