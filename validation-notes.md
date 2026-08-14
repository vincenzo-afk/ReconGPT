# Validation Notes

## Authorized passive end-to-end validation

- **Target:** `example.com` (public test target)
- **Run ID:** `8mMBjV34Yi-gfQ`
- **Run state:** Completed through the live server-sent event stream.
- **Result:** 17 findings from 18 queued passive modules; the historical Wayback source returned HTTP 429 and was surfaced as a source-specific limitation rather than being silently omitted.
- **Provider check:** IPinfo completed with one finding after correcting the server-only environment mapping from `IPINFO_TOKEN` to the configured `IPINFO_API_KEY` with backward compatibility.
- **Persistence check:** `reconRuns` stores the completed run with a 5,810-character grounded summary and a 116,706-character compacted evidence payload; `error` is null.

No active scanning, credential collection, or interaction with non-public systems was performed.
