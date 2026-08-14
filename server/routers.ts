import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { z } from "zod";
import * as db from "./db";
import { MODULES } from "./recon/modules";
import { completeAnalysis, providerStatus } from "./recon/service";

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
      return { enabledModules: settings?.enabledModulesJson ? JSON.parse(settings.enabledModulesJson) : MODULES.map(module => module.id), dorkIntensity: settings?.dorkIntensity || "balanced", preferredModel: settings?.preferredModel || "built-in", providerStatus: providerStatus() };
    }),
    save: protectedProcedure.input(z.object({ enabledModules: z.array(z.string()).max(64), dorkIntensity: z.enum(["focused", "balanced", "deep"]), preferredModel: z.string().max(128).optional() })).mutation(async ({ ctx, input }) => {
      await db.saveAnalystSettings({ userId: ctx.user.id, enabledModulesJson: JSON.stringify(input.enabledModules), dorkIntensity: input.dorkIntensity, preferredModel: input.preferredModel || "built-in" });
      return { success: true } as const;
    }),
  }),
  ai: router({
    chat: protectedProcedure.input(z.object({ messages: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().min(1).max(3000) })).min(1).max(10) })).mutation(async ({ ctx, input }) => {
      const settings = await db.getAnalystSettings(ctx.user.id);
      const content = await completeAnalysis([{ role: "system", content: "You are ReconGPT, an evidence-first OSINT analysis assistant. Help analysts plan legal, passive public-information research, interpret confirmed ReconGPT findings, and propose safe follow-ups. Never claim unverified facts and do not provide intrusive scanning, exploitation, credential attacks, or social-engineering instructions." }, ...input.messages], settings?.preferredModel || "built-in");
      return { content };
    }),
  }),
});

export type AppRouter = typeof appRouter;
