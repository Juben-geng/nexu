import { createRoute, z } from "@hono/zod-openapi";
import type { OpenAPIHono } from "@hono/zod-openapi";
import {
  createSessionSchema,
  sessionListResponseSchema,
  sessionResponseSchema,
  updateSessionSchema,
} from "@nexu/shared";
import { createId } from "@paralleldrive/cuid2";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { bots, sessions } from "../db/schema/index.js";

import type { AppBindings } from "../types.js";

const errorResponseSchema = z.object({
  message: z.string(),
});

const sessionIdParam = z.object({
  id: z.string(),
});

// --- Helper ---

function formatSession(row: typeof sessions.$inferSelect) {
  let metadata: Record<string, unknown> | null = null;
  if (row.metadata) {
    try {
      metadata = JSON.parse(row.metadata);
    } catch {
      metadata = null;
    }
  }
  return {
    id: row.id,
    botId: row.botId,
    sessionKey: row.sessionKey,
    channelType: row.channelType ?? null,
    channelId: row.channelId ?? null,
    title: row.title,
    status: row.status ?? "active",
    messageCount: row.messageCount ?? 0,
    lastMessageAt: row.lastMessageAt ?? null,
    metadata,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

// ============================================================
// Internal routes (before auth middleware)
// ============================================================

const createSessionRoute = createRoute({
  method: "post",
  path: "/api/internal/sessions",
  tags: ["Sessions (Internal)"],
  request: {
    body: {
      content: { "application/json": { schema: createSessionSchema } },
    },
  },
  responses: {
    201: {
      content: { "application/json": { schema: sessionResponseSchema } },
      description: "Session created or updated",
    },
    400: {
      content: { "application/json": { schema: errorResponseSchema } },
      description: "Invalid request",
    },
  },
});

const updateSessionInternalRoute = createRoute({
  method: "patch",
  path: "/api/internal/sessions/{id}",
  tags: ["Sessions (Internal)"],
  request: {
    params: sessionIdParam,
    body: {
      content: { "application/json": { schema: updateSessionSchema } },
    },
  },
  responses: {
    200: {
      content: { "application/json": { schema: sessionResponseSchema } },
      description: "Session updated",
    },
    404: {
      content: { "application/json": { schema: errorResponseSchema } },
      description: "Session not found",
    },
  },
});

export function registerSessionInternalRoutes(app: OpenAPIHono<AppBindings>) {
  // POST /api/internal/sessions — Gateway sidecar upserts a session
  app.openapi(createSessionRoute, async (c) => {
    const input = c.req.valid("json");

    // Verify botId exists
    const [bot] = await db
      .select({ id: bots.id })
      .from(bots)
      .where(eq(bots.id, input.botId));

    if (!bot) {
      return c.json({ message: "Bot not found" }, 400);
    }

    const now = new Date().toISOString();
    const id = createId();

    // Upsert on sessionKey
    await db
      .insert(sessions)
      .values({
        id,
        botId: input.botId,
        sessionKey: input.sessionKey,
        title: input.title,
        channelType: input.channelType,
        channelId: input.channelId,
        status: input.status ?? "active",
        messageCount: input.messageCount ?? 0,
        lastMessageAt: input.lastMessageAt,
        metadata: input.metadata ? JSON.stringify(input.metadata) : undefined,
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: sessions.sessionKey,
        set: {
          title: input.title,
          ...(input.channelType !== undefined && {
            channelType: input.channelType,
          }),
          ...(input.channelId !== undefined && {
            channelId: input.channelId,
          }),
          ...(input.status !== undefined && { status: input.status }),
          ...(input.messageCount !== undefined && {
            messageCount: input.messageCount,
          }),
          ...(input.lastMessageAt !== undefined && {
            lastMessageAt: input.lastMessageAt,
          }),
          ...(input.metadata !== undefined && {
            metadata: JSON.stringify(input.metadata),
          }),
          updatedAt: now,
        },
      });

    const [created] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.sessionKey, input.sessionKey));

    if (!created) {
      throw new Error("Session upsert failed");
    }

    return c.json(formatSession(created), 201);
  });

  // PATCH /api/internal/sessions/:id — update session
  app.openapi(updateSessionInternalRoute, async (c) => {
    const { id } = c.req.valid("param");
    const input = c.req.valid("json");

    const [existing] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.id, id));

    if (!existing) {
      return c.json({ message: "Session not found" }, 404);
    }

    const now = new Date().toISOString();

    await db
      .update(sessions)
      .set({
        ...(input.title !== undefined && { title: input.title }),
        ...(input.status !== undefined && { status: input.status }),
        ...(input.messageCount !== undefined && {
          messageCount: input.messageCount,
        }),
        ...(input.lastMessageAt !== undefined && {
          lastMessageAt: input.lastMessageAt,
        }),
        ...(input.metadata !== undefined && {
          metadata: JSON.stringify(input.metadata),
        }),
        updatedAt: now,
      })
      .where(eq(sessions.id, id));

    const [updated] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.id, id));

    if (!updated) {
      throw new Error("Session update failed");
    }

    return c.json(formatSession(updated), 200);
  });
}

// ============================================================
// User routes (after auth middleware)
// ============================================================

const listSessionsRoute = createRoute({
  method: "get",
  path: "/v1/sessions",
  tags: ["Sessions"],
  request: {
    query: z.object({
      botId: z.string().optional(),
      channelType: z.string().optional(),
      status: z.string().optional(),
      limit: z.coerce.number().int().min(1).max(100).default(20),
      offset: z.coerce.number().int().min(0).default(0),
    }),
  },
  responses: {
    200: {
      content: {
        "application/json": { schema: sessionListResponseSchema },
      },
      description: "Session list",
    },
  },
});

const getSessionRoute = createRoute({
  method: "get",
  path: "/v1/sessions/{id}",
  tags: ["Sessions"],
  request: {
    params: sessionIdParam,
  },
  responses: {
    200: {
      content: { "application/json": { schema: sessionResponseSchema } },
      description: "Session details",
    },
    404: {
      content: { "application/json": { schema: errorResponseSchema } },
      description: "Session not found",
    },
  },
});

export function registerSessionRoutes(app: OpenAPIHono<AppBindings>) {
  async function getUserBotIds(userId: string): Promise<string[]> {
    const userBots = await db
      .select({ id: bots.id })
      .from(bots)
      .where(eq(bots.userId, userId));
    return userBots.map((b) => b.id);
  }

  // GET /v1/sessions — list with filters
  app.openapi(listSessionsRoute, async (c) => {
    const userId = c.get("userId");
    const query = c.req.valid("query");
    const { limit, offset } = query;

    const botIds = await getUserBotIds(userId);
    if (botIds.length === 0) {
      return c.json({ sessions: [], total: 0, limit, offset }, 200);
    }

    // If botId filter specified, verify ownership
    if (query.botId && !botIds.includes(query.botId)) {
      return c.json({ sessions: [], total: 0, limit, offset }, 200);
    }

    const targetBotIds = query.botId ? [query.botId] : botIds;

    const conditions = [inArray(sessions.botId, targetBotIds)];
    if (query.channelType) {
      conditions.push(eq(sessions.channelType, query.channelType));
    }
    if (query.status) {
      conditions.push(eq(sessions.status, query.status));
    }

    const whereClause = and(...conditions);

    const [countResult] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(sessions)
      .where(whereClause);

    const rows = await db
      .select()
      .from(sessions)
      .where(whereClause)
      .orderBy(
        sql`${sessions.lastMessageAt} DESC NULLS LAST`,
        desc(sessions.createdAt),
      )
      .limit(limit)
      .offset(offset);

    return c.json(
      {
        sessions: rows.map(formatSession),
        total: countResult?.count ?? 0,
        limit,
        offset,
      },
      200,
    );
  });

  // GET /v1/sessions/:id — single session
  app.openapi(getSessionRoute, async (c) => {
    const userId = c.get("userId");
    const { id } = c.req.valid("param");

    const [session] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.id, id));

    if (!session) {
      return c.json({ message: "Session not found" }, 404);
    }

    // Verify ownership via bot
    const [bot] = await db
      .select({ id: bots.id })
      .from(bots)
      .where(and(eq(bots.id, session.botId), eq(bots.userId, userId)));

    if (!bot) {
      return c.json({ message: "Session not found" }, 404);
    }

    return c.json(formatSession(session), 200);
  });
}
