import React from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { getStoredToken } from "../../lib/api";

export const ProtectedRoute: React.FC = () => {
  const location = useLocation();
  const token = getStoredToken();

  if (!token) {
    // Redirect unauthenticated user to /login and preserve origin location
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <Outlet />;
};

export default ProtectedRoute;
