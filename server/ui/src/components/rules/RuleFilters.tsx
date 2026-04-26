import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface RuleFiltersProps {
  severity: string;
  collector: string;
  onSeverityChange: (value: string) => void;
  onCollectorChange: (value: string) => void;
  onClear: () => void;
}

export function RuleFilters({
  severity,
  collector,
  onSeverityChange,
  onCollectorChange,
  onClear,
}: RuleFiltersProps) {
  const hasFilters = severity !== "all" || collector !== "all";

  return (
    <div className="flex items-center gap-3">
      <Select value={severity} onValueChange={onSeverityChange}>
        <SelectTrigger className="w-[140px] h-8 text-xs">
          <SelectValue placeholder="Severity" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Severities</SelectItem>
          <SelectItem value="critical">Critical</SelectItem>
          <SelectItem value="high">High</SelectItem>
          <SelectItem value="medium">Medium</SelectItem>
          <SelectItem value="low">Low</SelectItem>
          <SelectItem value="info">Info</SelectItem>
        </SelectContent>
      </Select>

      <Select value={collector} onValueChange={onCollectorChange}>
        <SelectTrigger className="w-[140px] h-8 text-xs">
          <SelectValue placeholder="Collector" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Collectors</SelectItem>
          <SelectItem value="mcp">MCP</SelectItem>
          <SelectItem value="a2a">A2A</SelectItem>
          <SelectItem value="config">Config</SelectItem>
        </SelectContent>
      </Select>

      {hasFilters && (
        <Button
          variant="ghost"
          size="sm"
          onClick={onClear}
          className="h-8 px-2 text-xs text-muted-foreground"
        >
          <X className="h-3.5 w-3.5 mr-1" />
          Clear
        </Button>
      )}
    </div>
  );
}
