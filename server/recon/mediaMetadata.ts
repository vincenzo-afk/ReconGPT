import * as exifr from "exifr";
import { consentGranted, identityMetadata, redactCoordinates } from "./identitySafety";
import type { IdentityConsent } from "./types";

const MAX_BYTES = 12 * 1024 * 1024;
const allowedMime = new Set(["image/jpeg", "image/png", "image/webp", "image/tiff"]);

function validSignature(bytes: Buffer, mime: string) {
  if (mime === "image/jpeg") return bytes.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]));
  if (mime === "image/png") return bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (mime === "image/webp") return bytes.subarray(0, 4).toString("ascii") === "RIFF" && bytes.subarray(8, 12).toString("ascii") === "WEBP";
  return mime === "image/tiff" && (bytes.subarray(0, 4).toString("ascii") === "II*\u0000" || bytes.subarray(0, 4).toString("ascii") === "MM\u0000*");
}

export async function extractProvidedImageMetadata(bytes: Buffer, mime: string, consent: IdentityConsent | undefined) {
  if (!consentGranted(consent, "media-authorization-confirmed")) throw new Error("Media authorization must be confirmed before metadata extraction.");
  if (!allowedMime.has(mime) || bytes.length === 0 || bytes.length > MAX_BYTES || !validSignature(bytes, mime)) throw new Error("Provide a valid JPEG, PNG, WebP, or TIFF image smaller than 12 MB.");
  const parsed = await exifr.parse(bytes, { exif: true, gps: true, tiff: true, xmp: true, iptc: true, reviveValues: false }) || {};
  const latitude = typeof parsed.latitude === "number" ? parsed.latitude : null;
  const longitude = typeof parsed.longitude === "number" ? parsed.longitude : null;
  const safe = { make: parsed.Make || null, model: parsed.Model || null, software: parsed.Software || null, createDate: parsed.CreateDate || parsed.DateTimeOriginal || null, imageWidth: parsed.ImageWidth || null, imageHeight: parsed.ImageHeight || null, orientation: parsed.Orientation || null, gps: latitude !== null && longitude !== null ? redactCoordinates(latitude, longitude) : null, exactCoordinatesStored: false, ...identityMetadata(latitude !== null ? "location" : "public", "media-authorization-confirmed", latitude !== null ? "redacted" : "ephemeral") };
  return safe;
}
export const mediaMetadataForTests = { validSignature, MAX_BYTES };
