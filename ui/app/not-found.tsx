import { ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-[80vh] gap-4 text-center">
      <ShieldAlert className="w-12 h-12 text-zinc-600" />
      <h2 className="text-lg font-semibold text-zinc-200">Page not found</h2>
      <p className="text-sm text-zinc-400">The page you are looking for does not exist.</p>
      <Link
        href="/"
        className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-md text-sm text-white transition-colors"
      >
        Back to Dashboard
      </Link>
    </div>
  );
}
