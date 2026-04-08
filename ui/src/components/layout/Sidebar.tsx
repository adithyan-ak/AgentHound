import { X } from "lucide-react";
import { useUIStore } from "@/store/ui";
import { EntityInspector } from "@/components/inspector/EntityInspector";
import { ScrollArea } from "@/components/ui/scroll-area";

export function Sidebar() {
  const closeSidebar = useUIStore((s) => s.closeSidebar);

  return (
    <aside className="w-[380px] border-l bg-card flex-shrink-0 flex flex-col">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <span className="text-sm font-medium">Inspector</span>
        <button
          onClick={closeSidebar}
          className="rounded-md p-1 text-muted-foreground hover:text-foreground hover:bg-accent"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
      <ScrollArea className="h-full">
        <EntityInspector />
      </ScrollArea>
    </aside>
  );
}
