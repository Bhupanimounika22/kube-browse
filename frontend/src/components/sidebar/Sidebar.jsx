import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Chrome , Shredder ,Share } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

export default function Sidebar() {
  const [expanded, setExpanded] = useState(true);
  const { theme, toggleTheme } = useTheme();

  return (
    <motion.div 
      className={`h-screen bg-gray-900 dark:bg-gray-950 text-white ${expanded ? 'w-64' : 'w-20'} transition-all duration-300 flex flex-col`}
      initial={{ x: -100, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        {expanded ? (
          <h1 className="text-xl font-semibold">KubeBrowse</h1>
        ) : (
          <h1 className="text-xl font-semibold">KB</h1>
        )}
        <button 
          onClick={() => setExpanded(!expanded)} 
          className="p-2 rounded hover:bg-gray-800"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className={`h-5 w-5 transition-transform ${expanded ? '' : 'rotate-180'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={expanded ? "M11 19l-7-7 7-7m8 14l-7-7 7-7" : "M13 5l7 7-7 7M5 5l7 7-7 7"} />
          </svg>
        </button>
      </div>

      <nav className="flex-grow overflow-y-auto py-6">
        <div className="mb-6 px-4">
          <NavLink 
            to="/browser-session"
            className={({ isActive }) => 
              `flex items-center py-3 px-4 rounded-lg transition-colors ${isActive ? 'bg-blue-700' : 'hover:bg-gray-800'}`
            }
          >
            <Chrome />
            {expanded && <span className="ml-3">Browser Session</span>}
          </NavLink>
        </div>
      
        <div className="mb-6 px-4">
          <NavLink 
            to="/office-session"
            className={({ isActive }) => 
              `flex items-center py-3 px-4 rounded-lg transition-colors ${isActive ? 'bg-blue-700' : 'hover:bg-gray-800'}`
            }
          >
            <Shredder />
            {expanded && <span className="ml-3">Office Session</span>}
          </NavLink>
        </div>

        {/* share websocket_url connect button  */}
        <div className='mb-6 px-4'> 
          <NavLink 
            to="/share-ws-url"
            className={({ isActive }) => 
              `flex items-center py-3 px-4 rounded-lg transition-colors ${isActive ? 'bg-blue-700' : 'hover:bg-gray-800'}`
            }
          >
            <Share />
            {expanded && <span className="ml-3">Share WS URL</span>}
          </NavLink>

        </div>
      </nav>

      <div className="p-4 border-t border-gray-800 flex flex-col space-y-2">
        <NavLink 
          to="/settings"
          className={({ isActive }) => 
            `flex items-center py-3 px-4 rounded-lg transition-colors ${isActive ? 'bg-blue-700' : 'hover:bg-gray-800'}`
          }
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          {expanded && <span className="ml-3">Settings</span>}
        </NavLink>

        {expanded && (
          <button
            onClick={toggleTheme}
            className="flex items-center py-3 px-4 rounded-lg transition-colors hover:bg-gray-800"
          >
            {theme === 'dark' ? (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
                <span className="ml-3">Light Mode</span>
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
                <span className="ml-3">Dark Mode</span>
              </>
            )}
          </button>
        )}
        
        {!expanded && (
          <button
            onClick={toggleTheme}
            className="flex items-center justify-center py-3 px-4 rounded-lg transition-colors hover:bg-gray-800"
          >
            {theme === 'dark' ? (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
            )}
          </button>
        )}
      </div>
    </motion.div>
  );
} 