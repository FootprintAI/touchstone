"use client";

import { useState, type FormEvent } from "react";
import type { ScanInput } from "../lib/api";
import { isScannableUrl } from "../lib/url";

/** The server's cap on an uploaded SBOM/VEX document (D1). */
export const MAX_SBOM_DOCUMENT_BYTES = 2 * 1024 * 1024;

/**
 * One URL input, plus an optional SBOM/VEX the reviewer already has, by URL or
 * upload. A value that is not an absolute http(s) URL, or a file over the
 * cap, is refused here, before any request.
 */
export function ScanForm({ onScan, busy }: { onScan: (input: ScanInput) => void; busy: boolean }) {
  const [value, setValue] = useState("");
  const [sbomUrl, setSbomUrl] = useState("");
  const [sbomFile, setSbomFile] = useState<File | undefined>(undefined);
  const [invalid, setInvalid] = useState(false);
  const [sbomUrlInvalid, setSbomUrlInvalid] = useState(false);
  const [fileTooLarge, setFileTooLarge] = useState(false);
  const [fileError, setFileError] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const url = value.trim();
    const supplied = sbomUrl.trim();
    const ok = isScannableUrl(url);
    const suppliedOk = supplied === "" || isScannableUrl(supplied);
    const tooLarge = sbomFile !== undefined && sbomFile.size > MAX_SBOM_DOCUMENT_BYTES;
    setInvalid(!ok);
    setSbomUrlInvalid(!suppliedOk);
    setFileTooLarge(tooLarge);
    setFileError(false);
    if (!ok || !suppliedOk || tooLarge) {
      return;
    }
    const input: ScanInput = { url };
    if (supplied !== "") {
      input.sbomUrl = supplied;
    }
    if (sbomFile) {
      try {
        input.sbomDocument = await readFile(sbomFile);
      } catch {
        setFileError(true);
        return;
      }
    }
    onScan(input);
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
      <fieldset className="space-y-2 text-sm text-slate-700">
        <legend className="text-slate-600">
          Already have the vendor&apos;s SBOM or VEX? Add it (optional, High confidence):
        </legend>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="sbom-url">SBOM/VEX URL</label>
          <input
            id="sbom-url"
            name="sbomUrl"
            type="url"
            placeholder="https://vendor.example/sbom.json"
            value={sbomUrl}
            onChange={(e) => setSbomUrl(e.target.value)}
            aria-invalid={sbomUrlInvalid}
            aria-describedby={sbomUrlInvalid ? "sbom-url-error" : undefined}
            className="flex-1 rounded-md border border-slate-300 bg-white px-3 py-1 font-mono text-sm focus:border-slate-500 focus:outline-none"
          />
        </div>
        {sbomUrlInvalid && (
          <p id="sbom-url-error" className="text-sm text-red-700">
            Enter an absolute http:// or https:// URL for the SBOM/VEX, or leave it empty.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="sbom-file">SBOM/VEX file</label>
          <input
            id="sbom-file"
            name="sbomDocument"
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              setSbomFile(e.target.files?.[0]);
              setFileTooLarge(false);
            }}
            aria-invalid={fileTooLarge}
            aria-describedby={fileTooLarge ? "sbom-file-error" : undefined}
            className="text-sm"
          />
        </div>
        {fileTooLarge && (
          <p id="sbom-file-error" className="text-sm text-red-700">
            The SBOM/VEX file is too large; the limit is 2 MiB.
          </p>
        )}
        {fileError && <p className="text-sm text-red-700">The SBOM/VEX file could not be read.</p>}
        <p className="text-xs text-slate-500">CycloneDX, SPDX 2.3, OpenVEX or CSAF, as JSON, up to 2 MiB.</p>
      </fieldset>
    </form>
  );
}

/** The file's bytes. FileReader works in every browser and in jsdom. */
function readFile(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (result === null || typeof result === "string") {
        reject(new Error("could not read the SBOM/VEX file"));
      } else {
        resolve(new Uint8Array(result));
      }
    };
    reader.onerror = () => reject(reader.error ?? new Error("could not read the SBOM/VEX file"));
    reader.readAsArrayBuffer(file);
  });
}
