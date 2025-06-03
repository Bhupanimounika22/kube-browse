import { useEffect, useRef, useState } from 'react';
import useWebSocket from 'react-use-websocket';
import Guacamole from 'guacamole-common-js';
import states from '../lib/states';

/**
 * A custom hook that integrates react-use-websocket with Guacamole's WebSocketTunnel
 * 
 * @param {string} wsUrl - The WebSocket URL to connect to
 * @param {string} httpUrl - Fallback HTTP URL if WebSocket is not available
 * @param {boolean} forceHttp - Force using HTTP instead of WebSocket
 * @param {string} queryString - The query string to use for the connection
 * @returns {Object} - The Guacamole client, connection state, and error message
 */
const useGuacWebSocket = (wsUrl, httpUrl, forceHttp = false, queryString = '') => {
  const [connectionState, setConnectionState] = useState(states.IDLE);
  const [errorMessage, setErrorMessage] = useState('');
  const [isConnectionUnstable, setIsConnectionUnstable] = useState(false);
  const clientRef = useRef(null);
  const tunnelRef = useRef(null);

  // Custom WebSocketTunnel implementation that integrates with react-use-websocket
  class ReactWebSocketTunnel extends Guacamole.WebSocketTunnel {
    constructor(url) {
      super(url);
      this.receiveCallback = null;
      /* prevent parent from opening its own socket */
      this.websocket = null;
    }
    /* override connect so no extra socket is created */
    connect(data) {
      this._setState(Guacamole.Tunnel.State.CONNECTING);
      // react-use-websocket will now drive OPEN/CLOSED events
    }
    /* outgoing traffic must use react-use-websocket’s sendMessage */
    sendMessage(msg) {
      if (this.webSocketRef && this.webSocketRef.sendMessage) {
        this.webSocketRef.sendMessage(msg);
      }
    }
    setWebSocketRef(ref) {
      this.webSocketRef = ref;
    }
    setReceiveCallback(callback) {
      this.receiveCallback = callback;
    }
    handleMessage(event) {
      if (this.receiveCallback) {
        this.receiveCallback(event.data);
      }
    }
  }

  // Initialize the tunnel based on browser capabilities and settings
  const initializeTunnel = () => {
    if (window.WebSocket && !forceHttp) {
      const tunnel = new ReactWebSocketTunnel(wsUrl);
      tunnelRef.current = tunnel;
      return tunnel;
    } else {
      const tunnel = new Guacamole.HTTPTunnel(httpUrl, true);
      tunnelRef.current = tunnel;
      return tunnel;
    }
  };

  // Setup the Guacamole client when the component mounts or when the queryString changes
  useEffect(() => {
    if (!queryString) return;

    const tunnel = initializeTunnel();

    tunnel.onerror = (status) => {
      console.error(`Tunnel failed ${JSON.stringify(status)}`);
      setConnectionState(states.TUNNEL_ERROR);
      setErrorMessage(status.message || 'WebSocket tunnel error');
    };

    tunnel.onstatechange = (state) => {
      switch (state) {
        case Guacamole.Tunnel.State.CONNECTING:
          setConnectionState(states.CONNECTING);
          setIsConnectionUnstable(false);
          break;
        case Guacamole.Tunnel.State.OPEN:
          setConnectionState(states.CONNECTED);
          setIsConnectionUnstable(false);
          break;
        case Guacamole.Tunnel.State.UNSTABLE:
          // Handle unstable connection
          console.warn('WebSocket connection is unstable');
          setIsConnectionUnstable(true);
          break;
        case Guacamole.Tunnel.State.CLOSED:
          setConnectionState(states.DISCONNECTED);
          setIsConnectionUnstable(false);
          break;
        default:
          break;
      }
    };

    const client = new Guacamole.Client(tunnel);
    clientRef.current = client;

    client.onerror = (error) => {
      console.error(`Client error ${JSON.stringify(error)}`);
      setErrorMessage(error.message);
      setConnectionState(states.CLIENT_ERROR);
      client.disconnect();
    };

    client.onstatechange = (clientState) => {
      switch (clientState) {
        case 0: // IDLE
          setConnectionState(states.IDLE);
          break;
        case 2: // WAITING
          setConnectionState(states.WAITING);
          break;
        case 3: // CONNECTED
          setConnectionState(states.CONNECTED);
          break;
        default:
          break;
      }
    };

    // Connect with the query string
    if (queryString) {
      client.connect(queryString);
    }

    return () => {
      if (client) {
        client.disconnect();
      }
    };
  }, [wsUrl, httpUrl, forceHttp, queryString]);

  // Use react-use-websocket if we're using WebSocket tunnel
  const { sendMessage, lastMessage, readyState } = useWebSocket(
    !forceHttp && tunnelRef.current instanceof ReactWebSocketTunnel ? wsUrl : null,
    {
      onOpen: () => {
        console.log('WebSocket connection established');
        if (tunnelRef.current instanceof ReactWebSocketTunnel) {
          tunnelRef.current.setState(Guacamole.Tunnel.State.OPEN);
        }
      },
      onClose: () => {
        console.log('WebSocket connection closed');
        if (tunnelRef.current instanceof ReactWebSocketTunnel) {
          tunnelRef.current.setState(Guacamole.Tunnel.State.CLOSED);
        }
      },
      onError: (event) => {
        console.error('WebSocket error:', event);
        if (tunnelRef.current instanceof ReactWebSocketTunnel) {
          tunnelRef.current.setState(Guacamole.Tunnel.State.CLOSED);
          tunnelRef.current.onerror({ message: 'WebSocket error occurred' });
        }
      },
      onMessage: (event) => {
        if (tunnelRef.current instanceof ReactWebSocketTunnel) {
          tunnelRef.current.handleMessage(event);
        }
      },
      shouldReconnect: (closeEvent) => true,
      reconnectAttempts: 10,
      reconnectInterval: 3000
    }
  );

  // Integrate the WebSocket reference with our tunnel
  useEffect(() => {
    if (tunnelRef.current instanceof ReactWebSocketTunnel) {
      tunnelRef.current.setWebSocketRef({ sendMessage });
    }
  }, [sendMessage]);

  // Handle incoming messages from react-use-websocket
  useEffect(() => {
    if (lastMessage && tunnelRef.current instanceof ReactWebSocketTunnel) {
      tunnelRef.current.handleMessage(lastMessage);
    }
  }, [lastMessage]);

  return {
    client: clientRef.current,
    connectionState,
    errorMessage,
    readyState,
    isConnectionUnstable
  };
};

export default useGuacWebSocket;
