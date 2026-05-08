import React from 'react';

interface TrustScoreGaugeProps {
    score: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export function TrustScoreGauge({ score, riskLevel }: TrustScoreGaugeProps) {
    // Calculate stroke dash offset for circular progress
    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;

    // Color based on risk level
    const colors = {
        LOW: '#22c55e',      // green
        MEDIUM: '#eab308',   // yellow
        HIGH: '#f97316',     // orange
        CRITICAL: '#ef4444', // red
    };

    const color = colors[riskLevel];

    return (
        <div className="flex flex-col items-center gap-4">
            <div className="relative w-48 h-48">
                {/* Background circle */}
                <svg className="transform -rotate-90 w-48 h-48">
                    <circle
                        cx="96"
                        cy="96"
                        r={radius}
                        stroke="currentColor"
                        strokeWidth="12"
                        fill="none"
                        className="text-border"
                    />
                    {/* Progress circle */}
                    <circle
                        cx="96"
                        cy="96"
                        r={radius}
                        stroke={color}
                        strokeWidth="12"
                        fill="none"
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                    />
                </svg>

                {/* Score text */}
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <div className="text-4xl font-bold" style={{ color }}>
                        {Math.round(score)}
                    </div>
                    <div className="text-sm text-muted-foreground">TrustScore</div>
                </div>
            </div>

            {/* Risk level badge */}
            <div
                className={`px-4 py-2 rounded-md font-semibold text-sm ${riskLevel === 'CRITICAL' ? 'animate-pulse' : ''
                    }`}
                style={{
                    backgroundColor: `${color}20`,
                    color: color,
                    border: `2px solid ${color}`,
                }}
            >
                {riskLevel} RISK
            </div>
        </div>
    );
}
