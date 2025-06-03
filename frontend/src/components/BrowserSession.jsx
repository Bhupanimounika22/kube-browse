import { useState } from 'react';
import GuacClient from './GuacClient';

const isSecure = window.location.protocol === 'https:';
// const API_BASE = import.meta.env.VITE_GUAC_CLIENT_URL || `${isSecure ? 'https' : 'http'}://${location.host}`;
// const API_BASE = 'https://152.53.244.80:30006'
// const API_BASE = 'http://localhost:4567'
const API_BASE = '' // Use relative URLs to leverage Vite's proxy

const BrowserSession = () => {
  const [sessionState, setSessionState] = useState({
    connectionId: null,
    websocketUrl: null,
    status: 'idle',
    error: null
  });

  const createSession = async () => {
    try {
      setSessionState(prev => ({ ...prev, status: 'creating', error: null }));
      const response = await fetch(`${API_BASE}/test/deploy-browser`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          width: String(window.innerWidth * (window.devicePixelRatio || 1)),
          height: String(window.innerHeight * (window.devicePixelRatio || 1))
        })
      });
      if (!response.ok) {
        throw new Error('Failed to create office session');
      }
      const data = await response.json();
      const connectResponse = await fetch(`${API_BASE}/test/connect/${data.connection_id}`);
      if (!connectResponse.ok) {
        throw new Error('Failed to get connection URL');
      }
      const connectData = await connectResponse.json();
      setSessionState({
        connectionId: data.connection_id,
        websocketUrl: connectData.websocket_url,
        status: 'ready',
        error: null
      });
      console.log(connectData)
    } catch (error) {
      setSessionState(prev => ({
        ...prev,
        status: 'error',
        error: error.message
      }));
    }
  };

  const handleDisconnect = () => {
    if (sessionState.connectionId) {
      // Stop the session
      fetch(`${API_BASE}/sessions/${sessionState.connectionId}/stop`, {
        method: 'DELETE'
      }).catch(console.error);
    }
    console.log("Disconnected")
    setSessionState({
      connectionId: null,
      websocketUrl: null,
      status: 'idle',
      error: null
    });
  };

  return (
    <div className="flex flex-col items-center gap-4 p-4">
      {sessionState.status === 'idle' && (
        <button
          onClick={createSession}
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors"
        >
          Create Browser Session
        </button>
      )}
      {sessionState.status === 'creating' && (
        <div className="text-gray-600">
          Creating session...
        </div>
      )}
      {sessionState.status === 'error' && (
        <div className="text-red-500">
          Error: {sessionState.error}
        </div>
      )}
      {sessionState.status === 'ready' && sessionState.websocketUrl && (
        <div className="w-full">
          <div className="flex justify-between items-center mb-4">
            <span className="text-green-500">Session Ready</span>
            <button
              onClick={handleDisconnect}
              className="px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600 transition-colors"
            >
             Disconnect
            </button>
          </div>
          <div className="w-full h-[600px] border border-gray-300 rounded">
            <GuacClient
              query={{
                uuid: sessionState.connectionId,
                width: Math.round(window.innerWidth * (window.devicePixelRatio || 1)),
                height: Math.round(window.innerHeight * (window.devicePixelRatio || 1))
              }}
              connectionId={sessionState.connectionId}
              onDisconnect={handleDisconnect}
              OfficeSession={false}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default BrowserSession; 