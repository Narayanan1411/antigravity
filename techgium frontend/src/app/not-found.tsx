import Link from 'next/link';
import { Shield, ArrowLeft } from 'lucide-react';

export default function NotFound() {
    return (
        <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-6 max-w-md">
                <div className="mx-auto w-20 h-20 rounded-full bg-primary/10 flex items-center justify-center border border-primary/20">
                    <Shield className="w-10 h-10 text-primary" />
                </div>

                <div>
                    <h2 className="text-4xl font-black text-white mb-2">404</h2>
                    <p className="text-lg text-gray-400">Page not found</p>
                    <p className="text-sm text-gray-500 mt-2">
                        The resource you&apos;re looking for doesn&apos;t exist or has been moved.
                    </p>
                </div>

                <Link
                    href="/"
                    className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-white font-semibold rounded-lg hover:bg-primary/90 transition-colors"
                >
                    <ArrowLeft className="w-4 h-4" />
                    Back to Overview
                </Link>
            </div>
        </div>
    );
}
