import type { Express, Request, Response } from "express";
import { sdk } from "../_core/sdk";
import * as db from "../db";
import { parseCommunityControls } from "./identitySafety";
import { executeRecon } from "./service";
import { reconRequestSchema } from "./target";

function sendSse(res: Response, payload: unknown) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

export function registerReconStream(app: Express) {
  app.get("/api/recon/stream", async (req: Request, res: Response) => {
    res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.flushHeaders();
    let connected = true;
    res.on("close", () => { connected = false; });
    try {
      const user = await sdk.authenticateRequest(req);
      const parsed = reconRequestSchema.safeParse({ target: req.query.target, context: req.query.context || "", dorkIntensity: req.query.dorkIntensity || "balanced", enabledModules: typeof req.query.modules === "string" ? req.query.modules.split(",").filter(Boolean) : undefined, targetAuthorization: req.query.targetAuthorization, emailOwnershipConfirmed: req.query.emailOwnershipConfirmed, mediaAuthorizationConfirmed: req.query.mediaAuthorizationConfirmed, communityAdminConfirmed: req.query.communityAdminConfirmed });
      if (!parsed.success) {
        sendSse(res, { type: "failed", message: "Invalid recon request.", data: parsed.error.flatten(), timestamp: new Date().toISOString() });
        return res.end();
      }
      const settings = await db.getAnalystSettings(user.id);
      await executeRecon({ userId: user.id, rawTarget: parsed.data.target, context: parsed.data.context, options: { dorkIntensity: parsed.data.dorkIntensity, enabledModules: parsed.data.enabledModules, consent: { targetAuthorization: parsed.data.targetAuthorization, emailOwnershipConfirmed: parsed.data.emailOwnershipConfirmed, mediaAuthorizationConfirmed: parsed.data.mediaAuthorizationConfirmed, communityAdminConfirmed: parsed.data.communityAdminConfirmed }, communityControls: parseCommunityControls(settings?.communityControlsJson) }, emit: event => { if (connected) sendSse(res, event); } });
    } catch (error) {
      if (connected) sendSse(res, { type: "failed", message: error instanceof Error ? error.message : "Recon stream failed.", timestamp: new Date().toISOString() });
    } finally {
      res.end();
    }
  });
}
