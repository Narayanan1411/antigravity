import { Shield } from 'lucide-react';

export default function Loading() {
    return (
        <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-4">
                <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center border border-primary/20 animate-pulse">
                    <Shield className="w-8 h-8 text-primary" />
                </div>
                <div className="space-y-2">
                    <div className="h-2 w-48 bg-white/10 rounded-full mx-auto animate-pulse" />
                    <div className="h-2 w-32 bg-white/5 rounded-full mx-auto animate-pulse" />
                </div>
                <p className="text-sm text-gray-500">Loading...</p>
            </div>
        </div>
    );
}
