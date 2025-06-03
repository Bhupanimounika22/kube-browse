import Guacamole from 'guacamole-common-js';
import { useEffect, useRef, useState } from 'react';
import clipboard from '../lib/clipboard';
import GuacMouse from '../lib/GuacMouse';
import states from '../lib/states';
import Modal from './Modal';
import WebSocketControl from './WebSocketControl';
import useGuacWebSocket from '../hooks/useGuacWebSocket';
import { Toaster } from 'react-hot-toast';

// Set custom Mouse implementation
Guacamole.Mouse = GuacMouse.mouse;

// Define websocket and HTTP tunnel URLs
const isSecure = window.location.protocol === 'https:';
const wsUrl   = `${isSecure ? 'wss' : 'ws'}://${location.host}/websocket-tunnel`;
const httpUrl = `${isSecure ? 'https' : 'http'}://${location.host}/tunnel`;

// Convert query object to query string
const buildQueryString = (queryObj) => {
  if (!queryObj || typeof queryObj !== 'object') return '';
  
  const params = new URLSearchParams();
  
  for (const [key, value] of Object.entries(queryObj)) {
    if (value !== undefined && value !== null) {
      params.append(key, value.toString());
    }
  }
  
  return params.toString();
};

function GuacClient({ query, forceHttp = false, onDisconnect, connectionId , OfficeSession = true }) {
  const [connected, setConnected] = useState(false);
  
  // Convert query object to proper query string
  const queryString = buildQueryString(query);
  
  // Use our custom WebSocket hook for Guacamole
  const { client, connectionState, errorMessage, isConnectionUnstable } = useGuacWebSocket(
    wsUrl, 
    httpUrl, 
    forceHttp, 
    connected ? queryString : ''
  );
  
  const displayRef = useRef(null);
  const viewportRef = useRef(null);
  const modalRef = useRef(null);
  
  const clientRef = useRef(client); // Store client ref for access in other effects
  const displayObjRef = useRef(null);
  const keyboardRef = useRef(null);
  const mouseRef = useRef(null);
  const argumentsRef = useRef({});

  // Update client reference when it changes
  useEffect(() => {
    clientRef.current = client;
    if (client && connected) {
      // Set up display and clipboard when client becomes available
      setupClientDisplay();
      clipboard.install(client);
      
      // Set up clipboard events
      client.onclipboard = clipboard.onClipboard;
      
      // Test for argument mutability
      client.onargv = handleArgv;
    }
  }, [client, connected]);

  // Connect to the Guacamole server when query changes
  useEffect(() => {
    if (queryString && !connected) {
      setConnected(true);
    }
    
    return () => {
      if (clientRef.current) {
        clientRef.current.disconnect();
      }
    };
  }, [queryString, connected]);

  // Track connection state changes and notify parent component when disconnected
  useEffect(() => {
    if (connectionState === states.DISCONNECTED || connectionState === states.CLIENT_ERROR || connectionState === states.TUNNEL_ERROR) {
      if (connected && onDisconnect) {
        // Delay to allow potential reconnect attempts to happen first
        const timeout = setTimeout(() => {
          onDisconnect();
        }, 1000);
        return () => clearTimeout(timeout);
      }
    }
  }, [connectionState, connected, onDisconnect]);

  // Update modal when connection state changes
  useEffect(() => {
    if (modalRef.current) {
      modalRef.current.show(connectionState, errorMessage);
    }
  }, [connectionState, errorMessage]);

  // Handle argument value stream
  const handleArgv = (stream, mimetype, name) => {
    if (mimetype !== 'text/plain')
      return;

    const reader = new Guacamole.StringReader(stream);

    // Assemble received data into a single string
    let value = '';
    reader.ontext = (text) => {
      value += text;
    };

    // Test mutability once stream is finished
    reader.onend = () => {
      if (!clientRef.current) return;
      
      const stream = clientRef.current.createArgumentValueStream('text/plain', name);
      stream.onack = (status) => {
        if (status.isError()) {
          return;
        }
        argumentsRef.current[name] = value;
      };
    };
  };

  // Set up the display element
  const setupClientDisplay = () => {
    if (!clientRef.current || !displayRef.current) return;
    
    const display = clientRef.current.getDisplay();
    displayObjRef.current = display;
    
    const displayElement = display.getElement();
    
    // Set the display element to fill the width
    displayElement.style.width = '100%';
    displayElement.style.maxWidth = '100vw';
    
    displayRef.current.appendChild(displayElement);
    displayRef.current.addEventListener('contextmenu', (e) => {
      e.stopPropagation();
      if (e.preventDefault) {
        e.preventDefault();
      }
      e.returnValue = false;
    });
    
    // Set up mouse and keyboard
    setupMouseAndKeyboard();
    
    // Call resize immediately
    resize();
    
    // Focus the display element
    displayRef.current.focus();
    
    // Additional resize calls to handle delayed rendering
    setTimeout(resize, 100);
    setTimeout(resize, 500);
    setTimeout(resize, 1000);
  };

  // Set up mouse and keyboard handlers
  const setupMouseAndKeyboard = () => {
    if (!displayRef.current || !clientRef.current) return;
    
    const mouse = new Guacamole.Mouse(displayRef.current);
    mouseRef.current = mouse;
    
    // Hide software cursor when mouse leaves display
    mouse.onmouseout = () => {
      if (!displayObjRef.current) return;
      displayObjRef.current.showCursor(false);
    };

    // Focus handling
    displayRef.current.onclick = () => {
      displayRef.current.focus();
    };
    
    displayRef.current.onfocus = () => {
      displayRef.current.className = 'guac-display focus';
    };
    
    displayRef.current.onblur = () => {
      displayRef.current.className = 'guac-display';
    };

    // Set up keyboard
    const keyboard = new Guacamole.Keyboard(displayRef.current);
    keyboardRef.current = keyboard;
    
    installKeyboard();
    
    // Set up mouse event handlers
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = handleMouseState;
  };

  const send = (cmd) => {
    if (!clientRef.current) {
      return;
    }
    for (const c of cmd.data) {
      clientRef.current.sendKeyEvent(1, c.charCodeAt(0));
    }
  };

  const copy = (cmd) => {
    if (!clientRef.current) {
      return;
    }
    clipboard.cache = {
      type: 'text/plain',
      data: cmd.data
    };
    clipboard.setRemoteClipboard(clientRef.current);
  };

  const handleMouseState = (mouseState) => {
    if (!displayObjRef.current || !clientRef.current) return;
    
    const scaledMouseState = {
      ...mouseState,
      x: mouseState.x / displayObjRef.current.getScale(),
      y: mouseState.y / displayObjRef.current.getScale(),
    };
    clientRef.current.sendMouseState(scaledMouseState);
  };

  const resize = () => {
    if (!viewportRef.current || !displayObjRef.current || !clientRef.current) return;

    // Get the current viewport dimensions
    const viewportWidth = viewportRef.current.clientWidth;
    const viewportHeight = viewportRef.current.clientHeight;

    const remoteWidth = displayObjRef.current.getWidth();
    const remoteHeight = displayObjRef.current.getHeight();

    if (remoteWidth === 0 || remoteHeight === 0) {
      // If remote dimensions aren't available yet, try again shortly
      setTimeout(resize, 100);
      return;
    }

    // Calculate both horizontal and vertical scale factors
    const scaleX = viewportWidth / remoteWidth;
    const scaleY = viewportHeight / remoteHeight;
    
    // Use the smaller scale to ensure everything fits within the viewport
    const scale = Math.min(scaleX, scaleY);

    // Apply scale
    displayObjRef.current.scale(scale);

    // Get the actual pixel density for accurate resolution
    const pixelDensity = window.devicePixelRatio || 1;
    
    // Calculate the optimal resolution to send to the server
    const optimalWidth = Math.round(viewportWidth * pixelDensity);
    const optimalHeight = Math.round(viewportHeight * pixelDensity);
    
    // Send updated size to server
    clientRef.current.sendSize(optimalWidth, optimalHeight);
    
    // Center both horizontally and vertically
    if (displayRef.current) {
      const scaledWidth = remoteWidth * scale;
      const scaledHeight = remoteHeight * scale;
      
      // Center horizontally
      displayRef.current.style.marginLeft = scaledWidth < viewportWidth ? 
        `${(viewportWidth - scaledWidth) / 2}px` : '0';
      
      // Center vertically 
      displayRef.current.style.marginTop = scaledHeight < viewportHeight ? 
        `${(viewportHeight - scaledHeight) / 2}px` : '0';
    }
  };

  const installKeyboard = () => {
    if (!keyboardRef.current || !clientRef.current) return;
    
    keyboardRef.current.onkeydown = (keysym) => {
      clientRef.current.sendKeyEvent(1, keysym);
    };
    
    keyboardRef.current.onkeyup = (keysym) => {
      clientRef.current.sendKeyEvent(0, keysym);
    };
  };

  const uninstallKeyboard = () => {
    if (!keyboardRef.current) return;
    keyboardRef.current.onkeydown = keyboardRef.current.onkeyup = () => {};
  };

  const handleReconnect = () => {
    // Reset connection state and reconnect
    setConnected(false);
    
    // Clean up any existing display elements
    if (displayRef.current) {
      while (displayRef.current.firstChild) {
        displayRef.current.removeChild(displayRef.current.firstChild);
      }
    }
    
    // Reset references
    displayObjRef.current = null;
    
    // Reconnect after a small delay
    setTimeout(() => setConnected(true), 500);
  };

  const handleDisconnect = () => {
    if (clientRef.current) {
      // Properly clean up resources
      uninstallKeyboard();
      
      // Clear the display area
      if (displayRef.current) {
        while (displayRef.current.firstChild) {
          displayRef.current.removeChild(displayRef.current.firstChild);
        }
      }
      
      // Reset necessary state
      displayObjRef.current = null;
      
      // Actually disconnect from the client
      clientRef.current.disconnect();
      
      // Update connection state 
      setTimeout(() => {
        setConnected(false);
        
        // Notify parent component that we've disconnected
        if (onDisconnect) {
          onDisconnect();
        }
      }, 100);
    }
  };

  // Add a resize handler for when the component mounts
  useEffect(() => {
    const handleWindowResize = () => {
      resize();
    };
    
    // Add event listener for window resize
    window.addEventListener('resize', handleWindowResize);
    
    // Call resize immediately and then again after short delays
    handleWindowResize();
    const timeouts = [
      setTimeout(handleWindowResize, 100),
      setTimeout(handleWindowResize, 300),
      setTimeout(handleWindowResize, 500),
      setTimeout(handleWindowResize, 1000)
    ];
    
    // Cleanup
    return () => {
      window.removeEventListener('resize', handleWindowResize);
      timeouts.forEach(timeout => clearTimeout(timeout));
    };
  }, []); 
  
  return (
    <div className="relative w-full h-full">
      <div className="fixed top-0 left-0 w-screen h-screen overflow-hidden bg-black flex justify-center items-center" ref={viewportRef}>
        <div className="guac-display outline-none w-auto h-auto mx-auto" ref={displayRef} tabIndex="0">
          {/* The Guacamole display will be inserted here */}
        </div>
      </div>
      
      <Modal ref={modalRef} onRetry={handleReconnect} />
      
      <WebSocketControl 
        OfficeSession={OfficeSession}
        connectionState={connectionState} 
        onDisconnect={handleDisconnect} 
        connectionId={connectionId}
        isConnectionUnstable={isConnectionUnstable}
        errorMessage={errorMessage}
      />
      
      <Toaster position="top-right" />
    </div>
  );
}

export default GuacClient;
