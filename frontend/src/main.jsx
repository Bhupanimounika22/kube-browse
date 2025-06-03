import { ReactKeycloakProvider } from '@react-keycloak/web';
import Keycloak from 'keycloak-js';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';

import { ThemeProvider } from './context/ThemeContext';

import DashboardLayout from './layouts/DashboardLayout';
import ConnectionRoute from './routes/ConnectionRoute';
import DashboardRoute from './routes/DashboardRoute';
import EditConnectionRoute from './routes/EditConnectionRoute';
import NewConnectionRoute from './routes/NewConnectionRoute';
import NotFoundRoute from './routes/NotFoundRoute';
import SettingsRoute from './routes/SettingsRoute';

import './index.css';

// Create Keycloak instance only once
const keycloak = new Keycloak({
  url: 'http://localhost:9090',
  realm: 'vite-realm',
  clientId: 'kube-client',
});

const router = createBrowserRouter([
  {
    path: '/',
    element: <DashboardLayout />,
    children: [
      { index: true, element: <DashboardRoute /> },
      { path: 'connections/new', element: <NewConnectionRoute /> },
      { path: 'connections/:id', element: <ConnectionRoute /> },
      { path: 'connections/:id/edit', element: <EditConnectionRoute /> },
      { path: 'settings', element: <SettingsRoute /> },
    ],
  },
  { path: '*', element: <NotFoundRoute /> },
]);

const rootElement = document.getElementById('root');
if (rootElement) {
  const root = ReactDOM.createRoot(rootElement);

  root.render(
    <ReactKeycloakProvider
      authClient={keycloak}
      initOptions={{ onLoad: 'login-required', checkLoginIframe: false }}
      onEvent={(event, error) => {
        console.log('onKeycloakEvent', event, error);
      }}
      onTokens={(tokens) => {
        if (tokens.token) {
          sessionStorage.setItem('KEYCLOAK_TOKEN', tokens.token);
        } else {
          sessionStorage.removeItem('KEYCLOAK_TOKEN');
        }
      }}
      LoadingComponent={<div>Loading authentication...</div>}
    >
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    </ReactKeycloakProvider>
  );
}
