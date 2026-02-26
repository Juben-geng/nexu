import crypto from "node:crypto";
import type { OpenAPIHono } from "@hono/zod-openapi";
import { and, eq } from "drizzle-orm";
import { db } from "../db/index.js";
import {
  botChannels,
  channelCredentials,
  gatewayPools,
  webhookRoutes,
} from "../db/schema/index.js";
import { decrypt } from "../lib/crypto.js";
import type { AppBindings } from "../types.js";

// ── Slack signature verification ──────────────────────────────────────────

function verifySlackSignature(
  signingSecret: string,
  timestamp: string,
  rawBody: string,
  signature: string,
): boolean {
  const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
  if (Number.parseInt(timestamp, 10) < fiveMinutesAgo) return false;

  const sigBasestring = `v0:${timestamp}:${rawBody}`;
  const hmac = crypto
    .createHmac("sha256", signingSecret)
    .update(sigBasestring)
    .digest("hex");
  const expected = `v0=${hmac}`;

  if (signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

// ── Route registration ────────────────────────────────────────────────────

export function registerSlackEvents(app: OpenAPIHono<AppBindings>) {
  app.post("/api/slack/events", async (c) => {
    // 1. Read raw body (needed for signature verification)
    const rawBody = await c.req.text();

    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(rawBody) as Record<string, unknown>;
    } catch {
      return c.json({ error: "Invalid JSON" }, 400);
    }

    // 2. Handle url_verification challenge (Slack endpoint validation)
    if (payload.type === "url_verification") {
      return c.json({ challenge: payload.challenge });
    }

    // 3. Extract team_id from event payload
    const teamId = payload.team_id as string | undefined;
    if (!teamId) {
      return c.json({ error: "Missing team_id" }, 400);
    }

    // 4. Look up webhook route
    const [route] = await db
      .select()
      .from(webhookRoutes)
      .where(
        and(
          eq(webhookRoutes.channelType, "slack"),
          eq(webhookRoutes.externalId, teamId),
        ),
      );

    if (!route) {
      console.warn(
        `[slack-events] No webhook route for team_id=${teamId}`,
      );
      return c.json({ error: "Unknown workspace" }, 404);
    }

    // 5. Retrieve signing secret from credentials
    const [signingSecretRow] = await db
      .select({ encryptedValue: channelCredentials.encryptedValue })
      .from(channelCredentials)
      .where(
        and(
          eq(channelCredentials.botChannelId, route.botChannelId),
          eq(channelCredentials.credentialType, "signingSecret"),
        ),
      );

    if (!signingSecretRow) {
      console.error(
        `[slack-events] No signing secret for botChannelId=${route.botChannelId}`,
      );
      return c.json({ error: "Channel misconfigured" }, 500);
    }

    const signingSecret = decrypt(signingSecretRow.encryptedValue);

    // 6. Verify Slack request signature
    const timestamp = c.req.header("x-slack-request-timestamp") ?? "";
    const signature = c.req.header("x-slack-signature") ?? "";

    if (!timestamp || !signature) {
      return c.json({ error: "Missing Slack signature headers" }, 401);
    }

    if (!verifySlackSignature(signingSecret, timestamp, rawBody, signature)) {
      return c.json({ error: "Invalid signature" }, 401);
    }

    // 7. Find the gateway pod
    const [channel] = await db
      .select({ accountId: botChannels.accountId })
      .from(botChannels)
      .where(eq(botChannels.id, route.botChannelId));

    const accountId = channel?.accountId ?? `slack-${teamId}`;

    const [pool] = await db
      .select({ podIp: gatewayPools.podIp })
      .from(gatewayPools)
      .where(eq(gatewayPools.id, route.poolId));

    const podIp = pool?.podIp;

    // 8. Forward to gateway or log locally
    if (!podIp) {
      // Dev mode: no gateway pod, just log the event
      const eventType =
        (payload.event as Record<string, unknown> | undefined)?.type ?? "unknown";
      console.log(
        `[slack-events] team=${teamId} event=${eventType} (no gateway pod — logged only)`,
      );
      if (payload.event) {
        console.log(
          "[slack-events] payload:",
          JSON.stringify(payload.event, null, 2),
        );
      }
      return c.json({ ok: true });
    }

    // Forward to gateway pod
    const gatewayUrl = `http://${podIp}:18789/slack/events/${accountId}`;

    try {
      const gatewayResp = await fetch(gatewayUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Slack-Request-Timestamp": timestamp,
          "X-Slack-Signature": signature,
        },
        body: rawBody,
      });

      const respBody = await gatewayResp.text();
      return new Response(respBody, {
        status: gatewayResp.status,
        headers: { "Content-Type": "application/json" },
      });
    } catch (err) {
      console.error("[slack-events] Failed to forward to gateway:", err);
      // Return 200 to Slack to avoid retries — we'll handle the error internally
      return c.json({ ok: true });
    }
  });
}
