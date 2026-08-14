import { int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const reconRuns = mysqlTable("reconRuns", {
  id: varchar("id", { length: 32 }).primaryKey(),
  userId: int("userId").notNull().references(() => users.id),
  target: varchar("target", { length: 512 }).notNull(),
  targetType: mysqlEnum("targetType", ["domain", "ip", "email", "username", "company", "url", "phone", "asn"]).notNull(),
  context: text("context"),
  status: mysqlEnum("status", ["queued", "running", "completed", "failed"]).notNull().default("queued"),
  riskScore: int("riskScore").notNull().default(0),
  riskLevel: mysqlEnum("riskLevel", ["low", "medium", "high", "critical"]).notNull().default("low"),
  summary: text("summary"),
  resultsJson: text("resultsJson"),
  error: text("error"),
  startedAt: timestamp("startedAt").defaultNow().notNull(),
  completedAt: timestamp("completedAt"),
});

export const reconEvents = mysqlTable("reconEvents", {
  id: int("id").autoincrement().primaryKey(),
  runId: varchar("runId", { length: 32 }).notNull().references(() => reconRuns.id),
  moduleId: varchar("moduleId", { length: 96 }).notNull(),
  eventType: mysqlEnum("eventType", ["queued", "started", "finding", "completed", "failed", "notice"]).notNull(),
  message: text("message").notNull(),
  payloadJson: text("payloadJson"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const reconEntities = mysqlTable("reconEntities", {
  id: varchar("id", { length: 32 }).primaryKey(),
  runId: varchar("runId", { length: 32 }).notNull().references(() => reconRuns.id),
  entityType: mysqlEnum("entityType", ["domain", "subdomain", "ip", "email", "username", "organization", "url", "certificate", "asn", "phone"]).notNull(),
  value: varchar("value", { length: 1024 }).notNull(),
  label: varchar("label", { length: 1024 }).notNull(),
  confidence: int("confidence").notNull().default(70),
  metadataJson: text("metadataJson"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const entityRelationships = mysqlTable("entityRelationships", {
  id: varchar("id", { length: 32 }).primaryKey(),
  runId: varchar("runId", { length: 32 }).notNull().references(() => reconRuns.id),
  sourceEntityId: varchar("sourceEntityId", { length: 32 }).notNull().references(() => reconEntities.id),
  targetEntityId: varchar("targetEntityId", { length: 32 }).notNull().references(() => reconEntities.id),
  relationType: varchar("relationType", { length: 64 }).notNull(),
  evidence: text("evidence"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const analystSettings = mysqlTable("analystSettings", {
  userId: int("userId").primaryKey().references(() => users.id),
  enabledModulesJson: text("enabledModulesJson"),
  dorkIntensity: mysqlEnum("dorkIntensity", ["focused", "balanced", "deep"]).notNull().default("balanced"),
  preferredModel: varchar("preferredModel", { length: 128 }),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ReconRun = typeof reconRuns.$inferSelect;
export type InsertReconRun = typeof reconRuns.$inferInsert;
export type ReconEvent = typeof reconEvents.$inferSelect;
export type ReconEntity = typeof reconEntities.$inferSelect;
