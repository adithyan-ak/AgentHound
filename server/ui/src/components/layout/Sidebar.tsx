import { X } from "lucide-react";
import { useUIStore } from "@/store/ui";
import { EntityInspector } from "@/components/inspector/EntityInspector";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";

export function Sidebar() {
  const closeSidebar = useUIStore((s) => s.closeSidebar);

  return (
    <aside className="w-[380px] border-l bg-card flex-shrink-0 flex flex-col">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <span className="text-sm font-medium">Inspector</span>
        <Button onClick={closeSidebar} variant="ghost" size="icon" className="h-7 w-7">
          <X className="h-4 w-4" />
        </Button>
      </div>
      <ScrollArea className="h-full">
        <EntityInspector />
      </ScrollArea>
    </aside>
  );
}
