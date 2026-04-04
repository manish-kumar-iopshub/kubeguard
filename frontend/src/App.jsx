import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import UnhealthyPods from "./pages/UnhealthyPods";
import SecretLeakage from "./pages/SecretLeakage";
import DeploymentRisk from "./pages/DeploymentRisk";
import DeploymentDetail from "./pages/DeploymentDetail";
import ScannerSettings from "./pages/ScannerSettings";
import ApiPenTest from "./pages/ApiPenTest";
import ApiPenTestReport from "./pages/ApiPenTestReport";
import ScanDetail from "./pages/ScanDetail";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/unhealthy-pods" element={<UnhealthyPods />} />
        <Route path="/secret-leakage" element={<SecretLeakage />} />
        <Route path="/deployment-risk" element={<DeploymentRisk />} />
        <Route
          path="/api-pen-test/report/:scanId"
          element={<ApiPenTestReport />}
        />
        <Route path="/api-pen-test" element={<ApiPenTest />} />
        <Route
          path="/deployment-risk/:namespace/:deployment"
          element={<DeploymentDetail />}
        />
        <Route path="/settings" element={<ScannerSettings />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
