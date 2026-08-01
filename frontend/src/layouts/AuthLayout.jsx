import { Brand } from "../components/Brand";

export function AuthLayout({ children, caption }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-base p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-6">
          <Brand className="text-3xl" />
          <p className="text-sm font-mono text-muted mt-3">
            {caption ?? "Authenticate to manage your SSH key fleet"}
          </p>
        </div>
        <div className="bg-surface border border-line rounded-lg p-6 sm:p-8">
          {children}
        </div>
      </div>
    </div>
  );
}
