import { useState, useEffect, useRef } from "react";
import { Upload, Clipboard, ClipboardCheck, Download, X, ChevronDown, ChevronUp } from "lucide-react";
import toast, { Toaster } from "react-hot-toast";

/**
 * A collapsible control panel for WebSocket connection management
 * positioned in the bottom right of the screen with a high z-index
 */
function WebSocketControl({
  connectionState,
  onDisconnect,
  connectionId,
  OfficeSession = true,
  isConnectionUnstable = false,
  errorMessage = '',
}) {
  const [expanded, setExpanded] = useState(true);
  const [disconnecting, setDisconnecting] = useState(false);
  const [animationTimeout, setAnimationTimeout] = useState(null);
  // Upload state
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState(null);
  const [uploadSuccess, setUploadSuccess] = useState(false);
  const [uploadResponse, setUploadResponse] = useState(null);
  // Track history of all uploads
  const [uploadHistory, setUploadHistory] = useState([]);
  const fileInputRef = useRef();

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  // Track which upload logs are expanded in the modal
  const [expandedLogs, setExpandedLogs] = useState({});

  // copied to clipboard state
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);

  // Show toast when connection becomes unstable
  useEffect(() => {
    if (isConnectionUnstable) {
      toast.error("WebSocket connection is unstable", {
        id: "connection-unstable",
        duration: 3000,
        position: "top-right",
        icon: "⚠️",
        style: {
          borderRadius: "10px",
          background: "#FFF3CD",
          color: "#856404",
          border: "1px solid #FFEEBA",
        },
      });
    }
  }, [isConnectionUnstable]);

  // Show toast when there is a tunnel error
  useEffect(() => {
    if (connectionState === 'TUNNEL_ERROR') {
      toast.error(`Tunnel Error: ${errorMessage || 'Unable to connect'}`, {
        id: 'connection-error',
        duration: 3000,
        position: 'top-right',
        icon: '❌',
      });
    }
  }, [connectionState, errorMessage]);

  // Clear animation timeout on unmount
  useEffect(() => {
    return () => {
      if (animationTimeout) {
        clearTimeout(animationTimeout);
      }
    };
  }, [animationTimeout]);

  const toggleExpanded = () => {
    setExpanded(!expanded);
  };

  const handleDisconnect = () => {
    // Start the disconnecting animation
    setDisconnecting(true);

    // Set a timeout to actually perform the disconnect after animation
    const timeout = setTimeout(() => {
      if (onDisconnect) {
        onDisconnect();
      }
      // Reset the disconnecting state after a delay to complete the animation
      setTimeout(() => setDisconnecting(false), 500);
    }, 800); // Animation duration

    setAnimationTimeout(timeout);
  };

  // Upload handlers
  const handleFileUploadClick = () => {
    if (fileInputRef.current) fileInputRef.current.value = null;
    fileInputRef.current?.click();
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file || !connectionId) return;
    setUploading(true);
    setUploadProgress(0);
    setUploadError(null);
    setUploadSuccess(false);
    setUploadResponse(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const xhr = new window.XMLHttpRequest();
      xhr.open("POST", `/sessions/${connectionId}/upload`, true);
      xhr.withCredentials = false;
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          setUploadProgress(Math.round((event.loaded / event.total) * 100));
        }
      };
      xhr.onload = () => {
        setUploading(false);
        if (xhr.status >= 200 && xhr.status < 300) {
          setUploadSuccess(true);
          
          // Parse and store the response
          try {
            const response = JSON.parse(xhr.responseText);
            const timestamp = new Date();
            
            // Add timestamp and filename to the response
            const enrichedResponse = {
              ...response,
              timestamp,
              filename: file.name,
            };
            
            // Add the new upload to history
            setUploadHistory(prevHistory => [enrichedResponse, ...prevHistory]);
            setUploadResponse(enrichedResponse);
            
            // Check if malware was detected
            checkForMalware(enrichedResponse);
          } catch (parseErr) {
            console.error("Failed to parse upload response", parseErr);
          }
          
          setTimeout(() => setUploadSuccess(false), 2000);
        } else {
          setUploadError("Upload failed");
        }
      };
      xhr.onerror = () => {
        setUploading(false);
        setUploadError("Upload failed");
      };
      xhr.send(formData);
      xhr.onreadystatechange = () => {
        if (xhr.readyState === XMLHttpRequest.DONE) {
          console.log(xhr.responseText);
        }
      }
    } catch (err) {
      setUploading(false);
      setUploadError("Upload failed");
    }
  };
  
  // function to check for malware in the upload response
  const checkForMalware = (response) => {
    try {
      // Find the ClamAV result
      const clamavResult = response.results.find(result => result.service === "clamav");
      
      if (clamavResult && clamavResult.success && clamavResult.data?.response?.infected) {
        // Get the viruses list if available
        const viruses = clamavResult.data.response.viruses || [];
        const virusNames = viruses.length > 0 ? viruses.join(', ') : 'Unknown threat';
        
        // Show a prominent warning toast
        toast.error(
          <div>
            <div className="font-bold">😈 Malware Detected!</div>
            <div>The file may contain malicious content.</div>
            {viruses.length > 0 && <div className="text-xs mt-1">Detected: {virusNames}</div>}
          </div>,
          {
            id: 'malware-alert',
            duration: 6000,
            position: 'top-center',
            style: {
              background: '#FEE2E2',
              color: '#991B1B',
              border: '1px solid #F87171',
              padding: '16px',
              fontWeight: 'bold',
            },
          }
        );
        
        // Also look for the file name in the clamav response
        const infectedFiles = clamavResult.data.response.data?.result?.filter(file => file.is_infected) || [];
        
        if (infectedFiles.length > 0) {
          // Log detailed information about infected files
          console.warn('Infected files detected:', infectedFiles);
        }
      }
    } catch (err) {
      console.error("Error checking for malware:", err);
    }
  };

  // Share session handler
  const handleShareSession = async () => {
    if (!connectionId) return;

    try {
      const response = await fetch(`/test/share/${connectionId}`, {
        method: "GET",
        redirect: "follow",
      });

      if (response.ok) {
        const data = await response.json();
        const url = data.websocket_url;
        await navigator.clipboard.writeText(url);
        setCopiedToClipboard(true);
        setTimeout(() => setCopiedToClipboard(false), 2000);
      } else {
        console.error("Failed to share session");
      }
    } catch (error) {
      console.error("Error sharing session:", error);
    }
  };

  // Toggle log expansion in the modal
  const toggleLogExpansion = (index) => {
    setExpandedLogs(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  // Handler for showing upload logs modal
  const handleShowLogs = () => {
    if (uploadHistory.length > 0) {
      setIsModalOpen(true);
    } else {
      toast.error("No upload logs available", {
        duration: 2000,
        position: "top-right",
      });
    }
  };

  // Determine connection status for display
  const isConnected =
    connectionState === "CONNECTED" || connectionState === "WAITING";

  return (
    <>
      <Toaster />
      {/* Upload Logs Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[60]">
          <div className="bg-white rounded-lg shadow-lg max-w-3xl w-full max-h-[80vh] overflow-hidden flex flex-col text-gray-800">
            <div className="flex justify-between items-center p-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">File Upload History</h3>
              <button 
                onClick={() => setIsModalOpen(false)} 
                className="text-gray-500 hover:text-gray-700"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4 overflow-y-auto flex-1 text-gray-800">
              {uploadHistory.length === 0 ? (
                <div className="text-gray-500 text-center py-8">No upload history available</div>
              ) : (
                <div className="space-y-4">
                  {uploadHistory.map((entry, historyIndex) => (
                    <div key={historyIndex} className="border border-gray-200 rounded-lg overflow-hidden">
                      <div 
                        className="flex justify-between items-center p-3 bg-gray-50 cursor-pointer"
                        onClick={() => toggleLogExpansion(historyIndex)}
                      >
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-1 rounded text-white text-xs ${entry.success ? 'bg-green-500' : 'bg-red-500'}`}>
                            {entry.success ? 'Success' : 'Failed'}
                          </span>
                          <span className="font-medium text-gray-900">{entry.filename}</span>
                          <span className="text-sm text-gray-500">
                            {new Date(entry.timestamp).toLocaleString()}
                          </span>
                        </div>
                        {expandedLogs[historyIndex] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </div>

                      {expandedLogs[historyIndex] && (
                        <div className="p-3 border-t border-gray-200">
                          <div className="text-sm text-gray-700 mb-2">{entry.message}</div>
                          
                          <div className="space-y-3">
                            {entry.results.map((result, resultIndex) => (
                              <div key={resultIndex} className="border border-gray-200 rounded p-3">
                                <div className="flex justify-between items-center mb-2">
                                  <h4 className="font-semibold capitalize text-gray-900">{result.service}</h4>
                                  <span className={`px-2 py-0.5 text-xs rounded ${result.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                    {result.success ? 'Success' : 'Failed'}
                                  </span>
                                </div>
                                
                                {result.error && <div className="text-red-500 mb-2">Error: {result.error}</div>}
                                
                                {result.data && (
                                  <div className="text-sm text-gray-700">
                                    {/* File Upload Service */}
                                    {result.service === "file_upload" && result.data.status_code && (
                                      <div>Status Code: {result.data.status_code}</div>
                                    )}
                                    
                                    {/* ClamAV Service */}
                                    {result.service === "clamav" && result.data.response && (
                                      <div className="bg-gray-50 p-2 rounded mt-1 text-gray-800">
                                        {result.data.response.infected !== undefined && (
                                          <div className={`font-medium ${result.data.response.infected ? 'text-red-600' : 'text-green-600'}`}>
                                            {result.data.response.infected 
                                              ? '⚠️ Malware Detected' 
                                              : '✅ No Malware Detected'}
                                          </div>
                                        )}
                                        {result.data.response.data?.result?.map((file, idx) => (
                                          <div key={idx} className="mt-1">
                                            <div>File: {file.name}</div>
                                            <div>Infected: {file.is_infected ? 'Yes' : 'No'}</div>
                                            {file.viruses && file.viruses.length > 0 && (
                                              <div>Threats: {file.viruses.join(', ')}</div>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    
                                    {/* MinIO Storage Service */}
                                    {result.service === "minio" && (
                                      <div className="text-gray-700">
                                        <div>Bucket: {result.data.bucket}</div>
                                        <div>File: {result.data.object_name}</div>
                                        <div>Size: {formatBytes(result.data.size)}</div>
                                        <div>ETag: {result.data.etag}</div>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="border-t border-gray-200 p-4">
              <button 
                onClick={() => setIsModalOpen(false)} 
                className="px-4 py-2 bg-gray-200 text-gray-800 rounded hover:bg-gray-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <div
        className={`fixed bottom-5 right-5 z-50 bg-white rounded-lg shadow-lg overflow-hidden transition-all duration-300 ease-in-out min-w-[50px] max-w-[250px] ${
          expanded ? "w-[200px] h-auto" : "w-[50px] h-[50px]"
        }`}
      >
        <div
          className="flex justify-between items-center p-2.5 cursor-pointer bg-gray-100 border-b border-gray-200 select-none"
          onClick={toggleExpanded}
        >
          <div className="flex items-center gap-2">
            <div
              className={`w-3 h-3 rounded-full ${
                disconnecting
                  ? "bg-yellow-500 animate-pulse animate-pulse-glow"
                  : isConnectionUnstable
                  ? "bg-yellow-500 animate-pulse"
                  : isConnected
                  ? "bg-green-500 shadow-[0_0_5px_#4CAF50]"
                  : "bg-red-500 shadow-[0_0_5px_#f44336]"
              }`}
            ></div>
            {expanded && (
              <span className="text-sm text-gray-800 whitespace-nowrap overflow-hidden text-ellipsis">
                {disconnecting
                  ? "Disconnecting..."
                  : isConnectionUnstable
                  ? "Unstable"
                  : isConnected
                  ? "Connected"
                  : connectionState}
              </span>
            )}
          </div>
          <button className="bg-transparent border-none text-gray-600 cursor-pointer text-sm p-0 flex items-center justify-center">
            {expanded ? "▼" : "▲"}
          </button>
        </div>

        {expanded && (
          <div className="p-2.5">
            {/* Session share button */}
            <div className="mb-2 flex items-center gap-2">
              <button
                onClick={handleShareSession}
                title="Copy connection ID to clipboard"
                className="p-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors disabled:opacity-50"
                disabled={copiedToClipboard}
              >
                {copiedToClipboard ? (
                  <ClipboardCheck className="w-5 h-5" />
                ) : (
                  <Clipboard className="w-5 h-5" />
                )}
              </button>
            </div>

            {/* Upload UI */}
            {connectionId && OfficeSession && (
              <div className="mb-2 flex items-center gap-2">
                <button
                  onClick={handleFileUploadClick}
                  className="p-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors disabled:opacity-50"
                  disabled={uploading}
                  title="Upload File"
                >
                  <Upload className="w-5 h-5" />
                </button>
                
                {/* view upload logs button */}
                <button
                  onClick={handleShowLogs}
                  title="View file upload history"
                  className="p-2 bg-green-500 text-white rounded hover:bg-green-600 transition-colors disabled:opacity-50"
                  disabled={uploadHistory.length === 0}
                >
                  <Download className="w-5 h-5" />
                  {uploadHistory.length > 0 && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
                      {uploadHistory.length}
                    </span>
                  )}
                </button>
                
                <input
                  type="file"
                  ref={fileInputRef}
                  style={{ display: "none" }}
                  onChange={handleFileChange}
                  disabled={uploading}
                />
                
                {uploading && (
                  <div className="w-24">
                    <div className="h-2 bg-gray-200 rounded">
                      <div
                        className="h-2 bg-blue-500 rounded transition-all duration-300"
                        style={{ width: `${uploadProgress}%` }}
                      ></div>
                    </div>
                    <div className="text-xs text-gray-600 mt-1">
                      {uploadProgress}%
                    </div>
                  </div>
                )}
                {uploadSuccess && (
                  <div className="text-xs text-green-600 animate-pulse">✓</div>
                )}
                {uploadError && (
                  <div className="text-xs text-red-600">{uploadError}</div>
                )}
              </div>
            )}
            
            <button
              className={`w-full py-2 px-3 rounded text-white border-none transition-colors relative overflow-hidden ${
                disconnecting
                  ? "bg-yellow-500 cursor-wait"
                  : isConnected
                  ? "bg-red-500 hover:bg-red-700 cursor-pointer"
                  : "bg-gray-300 cursor-not-allowed"
              }`}
              onClick={handleDisconnect}
              disabled={!isConnected || disconnecting}
            >
              {disconnecting && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <svg
                    className="animate-spin -ml-1 mr-2 h-4 w-4 text-white"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                </span>
              )}
              <span className={disconnecting ? "opacity-0" : ""}>
                {disconnecting ? "Disconnecting..." : "Disconnect"}
              </span>
            </button>
          </div>
        )}
      </div>
    </>
  );
}

// Helper function to format bytes
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export default WebSocketControl;

