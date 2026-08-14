import { and, desc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { analystSettings, entityRelationships, InsertUser, reconEntities, reconEvents, reconRuns, users } from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function createReconRun(values: typeof reconRuns.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.insert(reconRuns).values(values);
}

export async function updateReconRun(id: string, values: Partial<typeof reconRuns.$inferInsert>) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(reconRuns).set(values).where(eq(reconRuns.id, id));
}

export async function appendReconEvent(values: typeof reconEvents.$inferInsert) {
  const db = await getDb();
  if (!db) return;
  await db.insert(reconEvents).values(values);
}

export async function saveEntitiesAndRelationships(
  entities: Array<typeof reconEntities.$inferInsert>,
  relationships: Array<typeof entityRelationships.$inferInsert>
) {
  const db = await getDb();
  if (!db) return;
  if (entities.length) await db.insert(reconEntities).values(entities);
  if (relationships.length) await db.insert(entityRelationships).values(relationships);
}

export async function getReconRunsForUser(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(reconRuns).where(eq(reconRuns.userId, userId)).orderBy(desc(reconRuns.startedAt)).limit(50);
}

export async function getReconRunForUser(userId: number, runId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(reconRuns).where(and(eq(reconRuns.userId, userId), eq(reconRuns.id, runId))).limit(1);
  return rows[0];
}

export async function getReconEventsForRun(runId: string) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(reconEvents).where(eq(reconEvents.runId, runId)).orderBy(reconEvents.createdAt);
}

export async function getAnalystSettings(userId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(analystSettings).where(eq(analystSettings.userId, userId)).limit(1);
  return rows[0];
}

export async function saveAnalystSettings(values: typeof analystSettings.$inferInsert) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.insert(analystSettings).values(values).onDuplicateKeyUpdate({
    set: {
      enabledModulesJson: values.enabledModulesJson,
      dorkIntensity: values.dorkIntensity,
      preferredModel: values.preferredModel,
    },
  });
}
