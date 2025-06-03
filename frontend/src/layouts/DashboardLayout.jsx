import { Outlet } from 'react-router-dom';
import Sidebar from '../components/sidebar/Sidebar';

export default function DashboardLayout() {
  return (
    <div className="flex h-screen bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors duration-200">
      <Sidebar />
      
      <div className="flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
} 