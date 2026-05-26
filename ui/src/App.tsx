import { Outlet } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "@/lib/invoke";
import { useStatus } from "@/hooks/useStatus";
import Sidebar from "./components/Sidebar";
import Unlock from "./screens/Unlock";
import NotRunningBanner from "./screens/NotRunningBanner";
import BootstrapWizard from "./screens/BootstrapWizard";

export default function App() {
  const [detect, setDetect] = useState<{ db_exists: boolean; socket_exists: boolean } | null>(null);
  const status = useStatus();

  useEffect(() => {
    const tick = () => api.detectState().then(setDetect);
    tick();
    const id = setInterval(tick, 2000);
    return () => clearInterval(id);
  }, []);

  if (!detect) return null;
  // proxyd reachable if status fetched successfully recently
  if (!status.data && (status.isError || !detect.socket_exists)) return <NotRunningBanner />;
  if (!detect.db_exists || status.data?.initialized === false) {
    return <BootstrapWizard onDone={() => api.detectState().then(setDetect)} />;
  }
  if (status.data?.locked) return <Unlock />;

  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
