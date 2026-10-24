import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Touchstone",
  description: "Paste a vendor's URL, get an evidence-graded CVE report.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased">
        <main className="mx-auto max-w-4xl space-y-8 px-4 py-10">
          <header>
            <h1 className="text-2xl font-bold">Touchstone</h1>
            <p className="text-sm text-slate-600">Paste a vendor&apos;s URL, get an evidence-graded CVE report.</p>
          </header>
          {children}
        </main>
      </body>
    </html>
  );
}
