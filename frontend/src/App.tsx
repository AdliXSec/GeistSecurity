import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import NewAuditPage from './pages/NewAuditPage';
import ProgressPage from './pages/ProgressPage';
import ReportPage from './pages/ReportPage';
import DocsPage from './pages/DocsPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Unified enterprise layout with consistent Navbar & Footer across all pages */}
        <Route element={<Layout footerVariant="full" />}>
          {/* Public routes */}
          <Route path="/" element={<HomePage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected operator workspace (requires active authentication) */}
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/audit/new" element={<NewAuditPage />} />
            <Route path="/audit/progress/:id" element={<ProgressPage />} />
            <Route path="/audit/report/:id" element={<ReportPage />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
