"use client";

import { useState, type FormEvent } from "react";
import { isScannableUrl } from "../lib/url";

/** One URL input. A value that is not an absolute http(s) URL is refused here, before any request. */
export function ScanForm({ onScan, busy }: { onScan: (url: string) => void; busy: boolean }) {
  const [value, setValue] = useState("");
  const [invalid, setInvalid] = useState(false);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const url = value.trim();
    const ok = isScannableUrl(url);
    setInvalid(!ok);
    if (ok) {
      onScan(url);
    }
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-2">
      <div className="flex gap-2">
        <label htmlFor="target-url" className="sr-only">
          Vendor URL
        </label>
        <input
          id="target-url"
          name="url"
          type="url"
          placeholder="https://vendor.example"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          aria-invalid={invalid}
          aria-describedby={invalid ? "target-url-error" : undefined}
          className="flex-1 rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm focus:border-slate-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {busy ? "Scanning…" : "Scan"}
        </button>
      </div>
      {invalid && (
        <p id="target-url-error" className="text-sm text-red-700">
          Enter an absolute http:// or https:// URL.
        </p>
      )}
    </form>
  );
}
