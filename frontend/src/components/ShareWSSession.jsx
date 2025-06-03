import { useState } from 'react';
import GuacClient from './GuacClient';

const isSecure = window.location.protocol === 'https:';
// const API_BASE = import.meta.env.VITE_GUAC_CLIENT_URL || `${isSecure ? 'https' : 'http'}://${location.host}`;
// const API_BASE = 'https://152.53.244.80:30006'
// const API_BASE = 'http://localhost:4567'
const API_BASE = '' // Use relative URLs to leverage Vite's proxy

const ShareWSSession = () => {
  const [sessionState, setSessionState] = useState({
    connectionId: null,
    websocketUrl: null,
    status: 'idle',
    error: null
  });
  const [inputUrl, setInputUrl] = useState('');

 

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

  const handleInputChange = (e) => {
    setInputUrl(e.target.value);
  };

  const handleUrlSubmit = async (e) => {
    e.preventDefault();
    try {
      setSessionState(prev => ({ ...prev, status: 'creating', error: null }));
      
      // Extract UUID from input URL
      const url = new URL(inputUrl, window.location.origin);
      const uuid = url.searchParams.get('uuid');

    //   console.log(uuid)
      
      if (!uuid) {
        throw new Error('Invalid URL: UUID parameter not found');
      }
      
      // Get connection details using the extracted UUID
      const connectResponse = await fetch(`${API_BASE}/test/connect/${uuid}`);
      if (!connectResponse.ok) {
        throw new Error('Failed to get connection URL');
      }
      
      const connectData = await connectResponse.json();
      setSessionState({
        connectionId: uuid,
        websocketUrl: connectData.websocket_url,
        status: 'ready',
        error: null
      });
      console.log(connectData);
    } catch (error) {
      setSessionState(prev => ({
        ...prev,
        status: 'error',
        error: error.message
      }));
    }
  };

  return (
    <div className="flex flex-col items-center gap-4 p-4">
      {sessionState.status === 'idle' && (
        <form onSubmit={handleUrlSubmit} className="flex flex-col w-full max-w-md gap-2">
          <div className="flex flex-col">
            <label htmlFor="wsUrl" className="text-sm text-gray-600 mb-1">
              Enter WebSocket Tunnel URL
            </label>
            <input
              id="wsUrl"
              type="text"
              value={inputUrl}
              onChange={handleInputChange}
              placeholder="/websocket-tunnel?uuid=..."
              className="px-4 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 text-black focus:ring-blue-500"
              required
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors"
          >
            Connect to Session
          </button>
        </form>
      )}
      {sessionState.status === 'creating' && (
        <div className="text-gray-600">
          Connecting to session...
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

export default ShareWSSession;

