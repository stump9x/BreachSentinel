import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext";
import AppShell from "./layout/AppShell";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import IndicatorsPage from "./pages/IndicatorsPage";
import ThreatsPage from "./pages/ThreatsPage";
import LeaksPage from "./pages/LeaksPage";
import OsintPage from "./pages/OsintPage";
import WorkersPage from "./pages/WorkersPage";
import IntelligencePage from "./pages/IntelligencePage";
import WatchRulesPage from "./pages/WatchRulesPage";
import FeedSourcesPage from "./pages/FeedSourcesPage";
import GithubScannerPage from "./pages/GithubScannerPage";
import LogsScannerPage from "./pages/LogsScannerPage";

function PublicOnly({ children }) {
  const { authed } = useAuth();
  if (authed) return <Navigate to="/" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicOnly>
            <LoginPage />
          </PublicOnly>
        }
      />
      <Route element={<AppShell />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/indicators" element={<IndicatorsPage />} />
        <Route path="/threats" element={<ThreatsPage />} />
        <Route path="/feeds" element={<FeedSourcesPage />} />
        <Route path="/leaks" element={<LeaksPage />} />
        <Route path="/osint" element={<OsintPage />} />
        <Route path="/github-scanner" element={<GithubScannerPage />} />
        <Route path="/logs-scanner" element={<LogsScannerPage />} />
        <Route path="/workers" element={<WorkersPage />} />
        <Route path="/watch-rules" element={<WatchRulesPage />} />
        <Route path="/intelligence" element={<IntelligencePage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
