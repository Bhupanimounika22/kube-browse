import { ReactKeycloakProvider } from '@react-keycloak/web';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './index.css';
import keycloak from './keycloak'; // Your keycloak config

import { ThemeProvider } from './context/ThemeContext';
import DashboardLayout from './layouts/DashboardLayout';

import BrowserSessionRoute from './routes/BrowserSessionRoute';
import NotFoundRoute from './routes/NotFoundRoute';
import OfficeSessionRoute from './routes/OfficeSessionRoute';
import SettingsRoute from './routes/SettingsRoute';
import ShareWSRoute from './routes/ShareWSRoute';

import DeploymentsRoute from './routes/DeploymentsRoute'; // import the DeploymentsRoute

const router = createBrowserRouter([
  {
    path: '/',
    element: <DashboardLayout />,
    children: [
      { index: true, element: <OfficeSessionRoute /> },
      { path: 'settings', element: <SettingsRoute /> },
      { path: 'office-session', element: <OfficeSessionRoute /> },
      { path: 'browser-session', element: <BrowserSessionRoute /> },
      { path: 'share-ws-url', element: <ShareWSRoute /> },
      { path: 'deployments', element: <DeploymentsRoute /> },  // add the deployments route here
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
