import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import UnhealthyPods from "./pages/UnhealthyPods";
import SecretLeakage from "./pages/SecretLeakage";
import DeploymentRisk from "./pages/DeploymentRisk";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/unhealthy-pods" element={<UnhealthyPods />} />
        <Route path="/secret-leakage" element={<SecretLeakage />} />
        <Route path="/deployment-risk" element={<DeploymentRisk />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
