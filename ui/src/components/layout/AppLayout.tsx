import { Outlet } from "react-router-dom";
import { NavBar } from "./NavBar";
import { Sidebar } from "./Sidebar";
import { useUIStore } from "@/store/ui";

export function AppLayout() {
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <NavBar />
      <div className="flex flex-1 overflow-hidden">
        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
        {sidebarOpen && <Sidebar />}
      </div>
    </div>
  );
}
