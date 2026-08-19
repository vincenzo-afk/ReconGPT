import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { z } from "zod";
import * as db from "./db";
import { MODULES } from "./recon/modules";
import { completeAnalysis, providerStatus } from "./recon/service";
import { extractProvidedImageMetadata } from "./recon/mediaMetadata";
import { defaultCommunityControls, normalizeCommunityScopes, parseCommunityControls, recordCommunityAudit } from "./recon/identitySafety";

async function saveCommunityControls(userId: number, config: ReturnType<typeof parseCommunityControls>) {
  const current = await db.getAnalystSettings(userId);
  await db.saveAnalystSettings({
    userId,
    enabledModulesJson: current?.enabledModulesJson || JSON.stringify(MODULES.map(module => module.id)),
    dorkIntensity: current?.dorkIntensity || "balanced",
    preferredModel: current?.preferredModel || "built-in",
    communityControlsJson: JSON.stringify(config),
  });
  return config;
}

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),
  recon: router({
    modules: publicProcedure.query(() => MODULES.map(module => ({ id: module.id, label: module.label, category: module.category, appliesTo: module.appliesTo, requiresKey: module.requiresKey || null }))),
    providers: protectedProcedure.query(() => providerStatus()),
    list: protectedProcedure.query(({ ctx }) => db.getReconRunsForUser(ctx.user.id)),
    get: protectedProcedure.input(z.object({ runId: z.string().min(5).max(32) })).query(async ({ ctx, input }) => {
      const run = await db.getReconRunForUser(ctx.user.id, input.runId);
      if (!run) return null;
      const events = await db.getReconEventsForRun(run.id);
      return { ...run, events, results: run.resultsJson ? JSON.parse(run.resultsJson) : null };
    }),
    compare: protectedProcedure.input(z.object({ olderRunId: z.string().min(5).max(32), newerRunId: z.string().min(5).max(32) })).query(async ({ ctx, input }) => {
      const [older, newer] = await Promise.all([db.getReconRunForUser(ctx.user.id, input.olderRunId), db.getReconRunForUser(ctx.user.id, input.newerRunId)]);
      if (!older || !newer) return null;
      const oldFindings = new Map<string, unknown>((JSON.parse(older.resultsJson || "{}")?.findings || []).map((finding: { title: string }) => [finding.title, finding]));
      const newFindings = new Map<string, unknown>((JSON.parse(newer.resultsJson || "{}")?.findings || []).map((finding: { title: string }) => [finding.title, finding]));
      return { older, newer, added: Array.from(newFindings.keys()).filter(key => !oldFindings.has(key)), removed: Array.from(oldFindings.keys()).filter(key => !newFindings.has(key)), scoreChange: newer.riskScore - older.riskScore };
    }),
  }),
  settings: router({
    get: protectedProcedure.query(async ({ ctx }) => {
      const settings = await db.getAnalystSettings(ctx.user.id);
      const isCommunityAdmin = ctx.user.role === "admin";
      return { enabledModules: settings?.enabledModulesJson ? JSON.parse(settings.enabledModulesJson) : MODULES.map(module => module.id), dorkIntensity: settings?.dorkIntensity || "balanced", preferredModel: settings?.preferredModel || "built-in", providerStatus: providerStatus(), canManageCommunity: isCommunityAdmin, communityControls: isCommunityAdmin ? parseCommunityControls(settings?.communityControlsJson) : defaultCommunityControls() };
    }),
    save: protectedProcedure.input(z.object({ enabledModules: z.array(z.string()).max(64), dorkIntensity: z.enum(["focused", "balanced", "deep"]), preferredModel: z.string().max(128).optional() })).mutation(async ({ ctx, input }) => {
      await db.saveAnalystSettings({ userId: ctx.user.id, enabledModulesJson: JSON.stringify(input.enabledModules), dorkIntensity: input.dorkIntensity, preferredModel: input.preferredModel || "built-in" });
      return { success: true } as const;
    }),
    saveCommunity: adminProcedure.input(z.object({ connectorEnabled: z.boolean(), paused: z.boolean(), retentionDays: z.number().int().min(1).max(30), scopes: z.array(z.object({ provider: z.enum(["discord", "telegram"]), scopeId: z.string().trim().min(1).max(128), label: z.string().trim().min(1).max(128) })).max(10) })).mutation(async ({ ctx, input }) => {
      const current = parseCommunityControls((await db.getAnalystSettings(ctx.user.id))?.communityControlsJson);
      const scopes = normalizeCommunityScopes(input.scopes);
      const config = recordCommunityAudit({ ...current, connectorEnabled: input.connectorEnabled && scopes.length > 0, paused: input.paused, retentionDays: input.retentionDays, scopes }, ctx.user.id, input.paused ? "paused" : current.paused && !input.paused ? "resumed" : "configured");
      await saveCommunityControls(ctx.user.id, config);
      return { success: true, controls: config } as const;
    }),
    purgeCommunity: adminProcedure.mutation(async ({ ctx }) => {
      const current = parseCommunityControls((await db.getAnalystSettings(ctx.user.id))?.communityControlsJson);
      const purged = recordCommunityAudit({ ...current, connectorEnabled: false, paused: true, scopes: [], lastPurgeAt: new Date().toISOString() }, ctx.user.id, "purged");
      await saveCommunityControls(ctx.user.id, purged);
      return { success: true, controls: purged, note: "Selected scope configuration was removed. ReconGPT stores no connected community messages or member data." } as const;
    }),
  }),
  ai: router({
    chat: protectedProcedure.input(z.object({ messages: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().min(1).max(3000) })).min(1).max(10) })).mutation(async ({ ctx, input }) => {
      const settings = await db.getAnalystSettings(ctx.user.id);
      const content = await completeAnalysis([{ role: "system", content: "You are ReconGPT, an evidence-first OSINT analysis assistant. Help analysts plan legal, passive public-information research, interpret confirmed ReconGPT findings, and propose safe follow-ups. Never claim unverified facts and do not provide intrusive scanning, exploitation, credential attacks, or social-engineering instructions." }, ...input.messages], settings?.preferredModel || "built-in");
      return { content };
    }),
  }),
  media: router({
    inspectMetadata: protectedProcedure.input(z.object({ filename: z.string().min(1).max(180), mime: z.enum(["image/jpeg", "image/png", "image/webp", "image/tiff"]), bytesBase64: z.string().min(1).max(16_800_000), mediaAuthorizationConfirmed: z.literal(true) })).mutation(async ({ input }) => {
      const bytes = Buffer.from(input.bytesBase64, "base64");
      return extractProvidedImageMetadata(bytes, input.mime, { mediaAuthorizationConfirmed: true });
    }),
  }),
});

export type AppRouter = typeof appRouter;
