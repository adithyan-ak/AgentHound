import { cn } from "@/lib/utils";
import { useCountUp } from "@/lib/useCountUp";

interface RadialGaugeProps {
  /** 0-100. */
  value: number;
  /** Severity color for the value-position pointer + scale marker. */
  valueColor?: string;
  /** Large readout shown inside the arc. Defaults to the rounded value. */
  readout?: string;
  /** Small caption under the readout. */
  caption?: string;
  size?: number;
  className?: string;
}

const PHOSPHOR = "#F5A623";
const TICK_OFF = "rgba(255,255,255,0.09)";
const SEGMENTS = 40;

/**
 * Segmented semicircular instrument gauge drawn in pure SVG (no chart dep).
 * Reads like a control-panel dial: discrete amber "phosphor" tick marks fill
 * up to `value`, a severity-colored pointer marks the current position, and a
 * large mono numeral types in on mount. Mechanical, precise, no glow.
 */
export function RadialGauge({
  value,
  valueColor,
  readout,
  caption,
  size = 208,
  className,
}: RadialGaugeProps) {
  const clamped = Math.max(0, Math.min(100, value));
  const animated = useCountUp(clamped, 950);
  const pointer = valueColor ?? PHOSPHOR;

  const pad = 16;
  const cx = size / 2;
  const cy = size / 2;
  const rOuter = size / 2 - pad;
  const tickLen = 15;
  const rInner = rOuter - tickLen;
  const height = cy + 36;

  const ticks = Array.from({ length: SEGMENTS }, (_, i) => {
    const frac = i / (SEGMENTS - 1);
    const pct = frac * 100;
    const angle = (180 - frac * 180) * (Math.PI / 180);
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const filled = pct <= animated;
    const leading = filled && (i + 1) / (SEGMENTS - 1) * 100 > animated;
    return {
      x1: cx + rInner * cos,
      y1: cy - rInner * sin,
      x2: cx + rOuter * cos,
      y2: cy - rOuter * sin,
      filled,
      leading,
    };
  });

  // severity pointer notch at the current value angle
  const pAngle = (180 - (animated / 100) * 180) * (Math.PI / 180);
  const pCos = Math.cos(pAngle);
  const pSin = Math.sin(pAngle);
  const pTipX = cx + (rInner - 3) * pCos;
  const pTipY = cy - (rInner - 3) * pSin;
  const pBaseX = cx + (rInner - 12) * pCos;
  const pBaseY = cy - (rInner - 12) * pSin;

  const display = readout ?? String(Math.round(animated));

  return (
    <div className={cn("relative", className)}>
      <svg
        width="100%"
        viewBox={`0 0 ${size} ${height}`}
        className="overflow-visible"
        role="img"
        aria-label={caption ? `${caption}: ${display}` : display}
      >
        {ticks.map((t, i) => (
          <line
            key={i}
            x1={t.x1}
            y1={t.y1}
            x2={t.x2}
            y2={t.y2}
            stroke={t.leading ? pointer : t.filled ? PHOSPHOR : TICK_OFF}
            strokeWidth={t.filled ? 3 : 2}
            strokeLinecap="butt"
            opacity={t.filled ? 1 : 0.9}
          />
        ))}

        {/* severity pointer */}
        <line
          x1={pBaseX}
          y1={pBaseY}
          x2={pTipX}
          y2={pTipY}
          stroke={pointer}
          strokeWidth={2.5}
          strokeLinecap="round"
        />

        {/* scale end labels */}
        <text x={cx - rOuter} y={cy + 16} textAnchor="middle" className="font-mono" style={{ fontSize: 9, fill: "#5C636E", letterSpacing: "0.1em" }}>
          0
        </text>
        <text x={cx + rOuter} y={cy + 16} textAnchor="middle" className="font-mono" style={{ fontSize: 9, fill: "#5C636E", letterSpacing: "0.1em" }}>
          100
        </text>

        {/* readout */}
        <text
          x={cx}
          y={cy - 6}
          textAnchor="middle"
          className="font-mono font-bold"
          style={{ fontSize: 46, fill: PHOSPHOR, letterSpacing: "-0.02em" }}
        >
          {display}
        </text>
        {caption && (
          <text
            x={cx}
            y={cy + 18}
            textAnchor="middle"
            className="font-mono"
            style={{
              fontSize: 10,
              letterSpacing: "0.22em",
              textTransform: "uppercase",
              fill: "#7A828E",
            }}
          >
            {caption}
          </text>
        )}
      </svg>
    </div>
  );
}
