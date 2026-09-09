import { generateKeyPairSync, randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { http, HttpResponse } from "msw";
import type { Response } from "node-fetch";
import { beforeEach, describe, expect, it } from "vitest";
import { UserRole } from "@shared/types";
import { Team, User, UserAuthentication } from "@server/models";
import { server as msw } from "@server/test/msw";
import { getTestServer, setSelfHosted } from "@server/test/support";
import serverEnv from "@server/env";
import env from "../env";
import {
  isAdminByGroups,
  verifySessionToken,
  type TRASessionClaims,
} from "../identity";

const server = getTestServer();
const EXCHANGE_URL = "http://identity.test/auth/exchange";
// The test database persists between runs, so keep emails unique per run.
const run = Date.now().toString(36);
const JANE = `jane-${run}@travelresorts.com`;
const JANE_SUB = randomUUID();
const SAM_SUB = randomUUID();
const SAM = `sam-${run}@travelresorts.com`;
const MALLORY = `mallory-${run}@travelresorts.com`;

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const { privateKey: otherPrivateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

function signSession(
  claims: Partial<TRASessionClaims> & Record<string, unknown> = {},
  key: string = privateKey
) {
  return jwt.sign(
    {
      sub: JANE_SUB,
      email: JANE,
      name: "Jane Doe",
      groups: [],
      jti: "jti-1",
      ...claims,
    },
    key,
    { algorithm: "RS256", expiresIn: "8h" }
  );
}

/** Stubs identity-api's exchange endpoint: each code maps to a token. */
function mockExchange(tokensByCode: Record<string, string>) {
  msw.use(
    http.post(EXCHANGE_URL, async ({ request }) => {
      const { code } = (await request.json()) as { code: string };
      const token = tokensByCode[code];
      return token
        ? HttpResponse.json({ token, expiresIn: 28800 })
        : HttpResponse.json(
            { error: "invalid or expired auth code" },
            { status: 400 }
          );
    })
  );
}

function location(res: Response) {
  return new URL(res.headers.get("location")!, "http://localhost");
}

describe("tra", () => {
  beforeEach(() => {
    setSelfHosted();
    // Store the key with literal "\n" escapes, as it is configured on Railway.
    env.TRA_JWT_PUBLIC_KEY = publicKey.replace(/\n/g, "\\n");
    env.TRA_ADMIN_GROUPS = "";
  });

  describe("start", () => {
    it("should redirect to identity-api login with the callback as redirectUrl", async () => {
      const res = await server.get("/auth/tra", { redirect: "manual" });
      expect(res.status).toEqual(302);

      const url = location(res);
      expect(url.origin + url.pathname).toEqual("http://identity.test/login");
      expect(url.searchParams.get("redirectUrl")).toEqual(
        `${env.URL}/auth/tra.callback`
      );
    });
  });

  describe("callback", () => {
    it("should reject a callback without an authCode", async () => {
      const res = await server.get("/auth/tra.callback", {
        redirect: "manual",
      });
      expect(res.status).toEqual(302);
      expect(location(res).search).toEqual("?notice=auth-error");
    });

    it("should provision the team and user and sign in", async () => {
      mockExchange({ "code-1": signSession() });

      const res = await server.get("/auth/tra.callback?authCode=code-1", {
        redirect: "manual",
      });
      expect(res.status).toEqual(302);
      expect(location(res).search).not.toContain("notice=");
      expect(res.headers.get("set-cookie")).toContain("accessToken=");

      const user = await User.findOne({
        where: { email: JANE },
      });
      expect(user).toBeTruthy();
      expect(user!.name).toEqual("Jane Doe");
      // On a fresh database the first sign-in creates the team and that user
      // becomes admin; on a reused local database they join the existing team.
      expect([UserRole.Admin, UserRole.Member]).toContain(user!.role);

      expect(await Team.findByPk(user!.teamId)).toBeTruthy();

      const auth = await UserAuthentication.findOne({
        where: { userId: user!.id },
      });
      expect(auth!.providerId).toEqual(JANE_SUB);
    });

    it("should reject a token signed with an unknown key", async () => {
      mockExchange({
        "code-2": signSession({ email: MALLORY }, otherPrivateKey),
      });

      const res = await server.get("/auth/tra.callback?authCode=code-2", {
        redirect: "manual",
      });
      expect(res.status).toEqual(302);
      expect(location(res).search).toEqual("?notice=auth-error");
      expect(await User.findOne({ where: { email: MALLORY } })).toBeNull();
    });

    it("should reject when identity-api refuses the code", async () => {
      mockExchange({});

      const res = await server.get("/auth/tra.callback?authCode=bad", {
        redirect: "manual",
      });
      expect(res.status).toEqual(302);
      expect(location(res).search).toEqual("?notice=auth-error");
    });

    it("should promote members of TRA_ADMIN_GROUPS to admin", async () => {
      const samToken = signSession({
        sub: SAM_SUB,
        email: SAM,
        name: "Sam Lee",
        groups: ["IT Department"],
      });
      mockExchange({
        "code-3": signSession(),
        "code-4": samToken,
        "code-5": samToken,
      });

      // First sign-in creates the team and makes that user an admin.
      await server.get("/auth/tra.callback?authCode=code-3", {
        redirect: "manual",
      });
      // In the test environment the current team is resolved by matching its
      // domain against env.URL (production self-hosted mode simply picks the
      // newest team), so point the new team at the configured URL.
      const jane = await User.findOne({
        where: { email: JANE },
      });
      const team = await Team.findByPk(jane!.teamId);
      await team!.update({ domain: "travelresorts.com" });
      serverEnv.URL = "https://travelresorts.com";

      // A second user joins as a member by default...
      await server.get("/auth/tra.callback?authCode=code-4", {
        redirect: "manual",
      });
      let sam = await User.findOne({
        where: { email: SAM },
      });
      expect(sam!.teamId).toEqual(jane!.teamId);
      expect(sam!.role).toEqual(UserRole.Member);

      // ...and is promoted once one of their groups is listed.
      env.TRA_ADMIN_GROUPS = "Platform Admins, it department";
      await server.get("/auth/tra.callback?authCode=code-5", {
        redirect: "manual",
      });
      sam = await User.findOne({ where: { email: SAM } });
      expect(sam!.role).toEqual(UserRole.Admin);
    });
  });

  describe("verifySessionToken", () => {
    it("should require sub, email and name", () => {
      const token = jwt.sign({ sub: "x", email: "x@y.z" }, privateKey, {
        algorithm: "RS256",
      });
      expect(() => verifySessionToken(token)).toThrow(/name/);
    });

    it("should reject HS256 tokens signed with the public key", () => {
      const token = jwt.sign(
        { sub: "x", email: "x@y.z", name: "X" },
        publicKey,
        { algorithm: "HS256" }
      );
      expect(() => verifySessionToken(token)).toThrow();
    });
  });

  describe("isAdminByGroups", () => {
    it("should match case-insensitively against the allow list", () => {
      expect(isAdminByGroups(["IT Department"], "it department")).toBe(true);
      expect(isAdminByGroups(["Sales"], "IT Department")).toBe(false);
      expect(isAdminByGroups(["Sales"], "")).toBe(false);
      expect(isAdminByGroups(undefined, "Sales")).toBe(false);
    });
  });
});
