import type { BetterAuthOptions } from "better-auth";
import { betterAuth } from "better-auth";
import Database from "better-sqlite3";

const databaseUrl = process.env.DATABASE_URL ?? "file:./nexu.db";
const dbPath = databaseUrl.replace(/^file:/, "");

const options: BetterAuthOptions = {
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  database: new Database(dbPath),
  emailAndPassword: {
    enabled: true,
  },
  trustedOrigins: [process.env.WEB_URL ?? "http://localhost:5173"],
};

export const auth = betterAuth(options);
