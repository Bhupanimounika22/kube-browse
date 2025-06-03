import { useState, useEffect } from 'react';
import GuacClient from './components/GuacClient';
import OfficeSession from './components/OfficeSession';

function App() {
  const [activeTab, setActiveTab] = useState('office'); // 'office' or 'manual'
  const [connect, setConnect] = useState(false);
  const [transitioning, setTransitioning] = useState(false);
  const [formData, setFormData] = useState({
    scheme: 'rdp',
    hostname: '0.0.0.0',
    port: '',
    user: '',
    pass: '',
    ignoreCert: true,
    security: '',
    forceHttp: false,
    width: window.innerWidth,
    height: window.innerHeight
  });

  useEffect(() => {
    // Load saved connection details from localStorage on mount
    if (window.localStorage && window.localStorage.getItem('query')) {
      try {
        const query = JSON.parse(window.localStorage.getItem('query'));
        setFormData({
          scheme: query.scheme || 'rdp',
          hostname: query.hostname || '0.0.0.0',
          port: query.port || '',
          user: query.username || '',
          pass: query.password || '',
          ignoreCert: query['ignore-cert'] !== false,
          security: query.security || '',
          forceHttp: query.forceHttp || false,
          width: window.innerWidth,
          height: window.innerHeight
        });
      } catch (e) {
        window.localStorage.setItem('query', '{}');
      }
    }

    // Update dimensions if window is resized before connection
    const handleResize = () => {
      setFormData(prevData => ({
        ...prevData,
        width: window.innerWidth,
        height: window.innerHeight
      }));
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleInputChange = (e) => {
    const { id, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [id]: type === 'checkbox' ? checked : value
    });
  };

  const buildQueryObj = () => {
    return {
      scheme: formData.scheme,
      hostname: formData.hostname,
      port: formData.port,
      'ignore-cert': formData.ignoreCert,
      security: formData.security,
      username: formData.user,
      password: formData.pass,
      width: Math.round(formData.width * (window.devicePixelRatio || 1)),
      height: Math.round(formData.height * (window.devicePixelRatio || 1))
    };
  };

  const buildQueryString = () => {
    const queryString = [];
    const queryObj = buildQueryObj();
    
    for (const [k, v] of Object.entries(queryObj)) {
      if (v) {
        queryString.push(`${k}=${encodeURIComponent(v)}`);
      }
    }
    
    console.log(queryString.join("&"))
    
    return queryString.join("&");
  };

  const getScrubbedQuery = () => {
    return buildQueryString().replace(/password=[^&]+/, 'password=****');
  };

  const handleConnect = () => {
    if (window.localStorage) {
      window.localStorage.setItem('query', JSON.stringify(buildQueryObj()));
    }
    setTransitioning(true);
    setTimeout(() => {
      setConnect(true);
      setTransitioning(false);
    }, 300);
  };

  const handleDisconnected = () => {
    setTransitioning(true);
    setTimeout(() => {
      setConnect(false);
      setTransitioning(false);
    }, 300);
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-4">
      <div className="flex justify-center mb-6">
        <div className="inline-flex rounded-lg border border-gray-700 bg-gray-800 p-1">
          <button
            className={`px-4 py-2 rounded-md text-sm font-medium ${
              activeTab === 'office'
                ? 'bg-blue-600 text-white'
                : 'text-gray-300 hover:text-white'
            }`}
            onClick={() => setActiveTab('office')}
          >
            Office Session
          </button>
          <button
            className={`px-4 py-2 rounded-md text-sm font-medium ${
              activeTab === 'manual'
                ? 'bg-blue-600 text-white'
                : 'text-gray-300 hover:text-white'
            }`}
            onClick={() => setActiveTab('manual')}
          >
            Manual Connection
          </button>
        </div>
      </div>

      <div className={`transition-opacity duration-300 ${transitioning ? 'opacity-0' : 'opacity-100'}`}>
        {activeTab === 'office' ? (
          <OfficeSession />
        ) : !connect ? (
          <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
            <h1 className="text-3xl font-bold mb-4 text-center text-white">React Guacamole client example</h1>
            <p className="mb-6 text-center text-gray-300">Enter connection information to connect</p>

            <div className="mb-4">
              <label htmlFor="scheme" className="block text-gray-300 mb-1">Scheme/Protocol</label>
              <input 
                type="text" 
                id="scheme" 
                value={formData.scheme} 
                onChange={handleInputChange} 
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-white"
              />
            </div>

            <div className="mb-4">
              <label htmlFor="hostname" className="block text-gray-300 mb-1">Hostname or IP Address</label>
              <input 
                type="text" 
                id="hostname" 
                value={formData.hostname} 
                onChange={handleInputChange} 
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-white"
              />
            </div>

            <div className="mb-4">
              <label htmlFor="port" className="block text-gray-300 mb-1">Port (if not default)</label>
              <input 
                type="text" 
                id="port" 
                value={formData.port} 
                onChange={handleInputChange} 
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-white"
              />
            </div>

            <div className="mb-4">
              <label htmlFor="user" className="block text-gray-300 mb-1">User name</label>
              <input 
                type="text" 
                id="user" 
                value={formData.user} 
                onChange={handleInputChange} 
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-white"
              />
            </div>

            <div className="mb-4">
              <label htmlFor="pass" className="block text-gray-300 mb-1">Password</label>
              <input 
                type="password" 
                id="pass" 
                value={formData.pass} 
                onChange={handleInputChange} 
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-white"
              />
            </div>

            <div className="mb-4 flex items-center">
              <label htmlFor="ignoreCert" className="text-gray-300 mr-2">Ignore Certificate</label>
              <input 
                type="checkbox" 
                id="ignoreCert" 
                checked={formData.ignoreCert} 
                onChange={handleInputChange} 
                className="h-4 w-4 accent-blue-500"
              />
            </div>

            <div className="mb-4">
              <label htmlFor="security" className="block text-gray-300 mb-1">Security</label>
              <input 
                type="text" 
                id="security" 
                value={formData.security} 
                onChange={handleInputChange} 
                placeholder="type nla here for Network Level Authentication" 
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-white"
              />
            </div>

            <div className="mb-4">
              <label className="block text-gray-300 mb-1">Query string</label>
              <span className="block p-2 bg-gray-700 rounded text-gray-300 overflow-x-auto whitespace-pre font-mono text-sm">
                {getScrubbedQuery()}
              </span>
            </div>

            <div className="mb-4 flex items-center">
              <label htmlFor="forceHttp" className="text-gray-300 mr-2">Force HTTP Tunnel</label>
              <input 
                type="checkbox" 
                id="forceHttp" 
                checked={formData.forceHttp} 
                onChange={handleInputChange} 
                className="h-4 w-4 accent-blue-500"
              />
            </div>

            <div className="text-center mt-6">
              <button 
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded transition-colors" 
                onClick={handleConnect}
              >
                Connect
              </button>
            </div>
          </div>
        ) : (
          <GuacClient 
            query={buildQueryString()} 
            forceHttp={formData.forceHttp} 
            onDisconnected={handleDisconnected}
          />
        )}
      </div>
    </div>
  );
}

export default App;