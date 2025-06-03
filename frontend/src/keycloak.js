// src/keycloak.js
import Keycloak from 'keycloak-js';

const keycloak = new Keycloak({
  url: 'http://localhost:8080', // or your Keycloak server
  realm: 'vite-realm',
  clientId: 'kube-client',
});

export default keycloak;
