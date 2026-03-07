"use client"
import { RadialBarChart, RadialBar, PolarAngleAxis } from "recharts"

interface Props { score: number }

export function ScoreGauge({ score }: Props) {
  const color =
    score >= 80 ? "#f87171"
    : score >= 60 ? "#fb923c"
    : score >= 40 ? "#fbbf24"
    : "#4ade80"

  return (
    <div className="relative flex items-center justify-center max-w-[180px] w-full aspect-square">
      <RadialBarChart
        width={180}
        height={180}
        innerRadius={60}
        outerRadius={85}
        data={[{ value: score, fill: color }]}
        startAngle={210}
        endAngle={-30}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar dataKey="value" angleAxisId={0} background={{ fill: "#1e293b" }} />
      </RadialBarChart>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-muted-foreground">risk score</span>
      </div>
    </div>
  )
}
