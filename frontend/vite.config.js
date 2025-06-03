// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const guacClient = process.env.GUAC_CLIENT_URL || 'https://152.53.244.80:30006'
console.log(`Using Guacamole client URL: ${guacClient}`)

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/tunnel': {
        target: guacClient,
        changeOrigin: true,
        ws: false,
        secure: false, // Ignore certificate validation
        timeout: 60000, // Increase timeout to 60 seconds
        proxyTimeout: 60000,
      },
      '/test': {
        target: guacClient,
        changeOrigin: true,
        ws: false,
        secure: false, // Ignore certificate validation
        timeout: 60000, // Increase timeout to 60 seconds
        proxyTimeout: 60000,
      },
      '/sessions': {
        target: guacClient,
        changeOrigin: true,
        ws: false,
        secure: false, // Ignore certificate validation
        timeout: 60000, // Increase timeout to 60 seconds
        proxyTimeout: 60000,
      },
      '/websocket-tunnel': {
        target: guacClient,
        changeOrigin: true,
        ws: true,
        secure: false, // Ignore certificate validation
        timeout: 120000, // Increase timeout to 120 seconds
        proxyTimeout: 120000,
        configure: (proxy, _options) => {
          // Increase buffer size to handle larger WebSocket frames
          proxy.options.buffer = Buffer.alloc(1024 * 1024);
          
          proxy.on('error', (err, req, res) => {
            console.log('Proxy error:', err);
            
            // Prevent additional writes to broken connections
            if (err.code === 'EPIPE' || err.code === 'ECONNRESET') {
              console.log('Connection closed by remote host. Preventing further writes.');
              if (res && !res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'text/plain' });
                res.end('WebSocket connection error. Please refresh the page to reconnect.');
              }
            }
          });
          
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            // Ensure WebSocket headers are preserved
            if (req.headers['sec-websocket-key']) {
              if (!proxyReq.getHeader('connection')) {
                proxyReq.setHeader('connection', 'upgrade');
              }
              if (!proxyReq.getHeader('upgrade')) {
                proxyReq.setHeader('upgrade', 'websocket');
              }
              
              // Add additional headers that might help with connection stability
              proxyReq.setHeader('pragma', 'no-cache');
              proxyReq.setHeader('cache-control', 'no-cache');
            }
            
            // Log outgoing proxy requests
            console.log(`Proxying WebSocket request to: ${req.url}`);
          });
          
          proxy.on('proxyRes', (proxyRes, req, res) => {
            // Log successful responses
            console.log(`Proxy response: ${proxyRes.statusCode} for ${req.url}`);
          });
          
          proxy.on('upgrade', (req, socket, head) => {
            console.log('WebSocket upgrade initiated for:', req.url);
            
            // Add error handler to the socket
            socket.on('error', (err) => {
              console.error('WebSocket socket error:', err);
              // Close the socket gracefully to prevent EPIPE errors
              try {
                if (!socket.destroyed) {
                  socket.end();
                }
              } catch (e) {
                console.error('Error while closing socket:', e);
              }
            });
            
            // Add close handler
            socket.on('close', () => {
              console.log('WebSocket connection closed for:', req.url);
            });
            
            // Keep socket alive
            socket.setKeepAlive(true);
            
            // Increase socket timeout
            socket.setTimeout(120000);
          });
          
          // Add general proxy error handling
          proxy.on('econnreset', (err, req, res, target) => {
            console.warn('Connection reset by peer:', err);
            
            // Try to gracefully handle the reset
            if (res && !res.headersSent) {
              res.writeHead(502, { 'Content-Type': 'text/plain' });
              res.end('Connection reset by server. Please refresh the page to reconnect.');
            }
          });
          
          proxy.on('end', () => {
            console.log('Proxy connection ended');
          });
        }
      },
    },
  },
})
