'use client';

import { AlertTriangle, RotateCcw } from 'lucide-react';

export default function Error({
    error,
    reset,
}: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return (
        <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-6 max-w-md">
                <div className="mx-auto w-20 h-20 rounded-full bg-critical/10 flex items-center justify-center border border-critical/20">
                    <AlertTriangle className="w-10 h-10 text-critical" />
                </div>

                <div>
                    <h2 className="text-2xl font-bold text-white mb-2">Something went wrong</h2>
                    <p className="text-sm text-gray-400">
                        {error.message || 'An unexpected error occurred while rendering this page.'}
                    </p>
                </div>

                <button
                    onClick={reset}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-white font-semibold rounded-lg hover:bg-primary/90 transition-colors"
                >
                    <RotateCcw className="w-4 h-4" />
                    Try Again
                </button>
            </div>
        </div>
    );
}
