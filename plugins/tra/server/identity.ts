import jwt from "jsonwebtoken";
import { AuthenticationError } from "@server/errors";
import fetch from "@server/utils/fetch";
import env from "./env";

/**
 * Claims carried by a `tra_session` JWT issued by identity-api. Mirrors
 * `JwtPayload` in tra-summit's `@tra/identity-client`; identity-api is the
 * source of truth.
 */
export type TRASessionClaims = {
  /** Entra ID object id of the user */
  sub: string;
  email: string;
  name: string;
  jobTitle?: string | null;
  /** Entra ID group display names the user belongs to */
  groups?: string[];
  iat: number;
  exp: number;
  jti: string;
};

/**
 * Redeems the one-time `authCode` that identity-api appends to the redirect
 * URL after a successful Entra ID login, returning the session JWT.
 *
 * @param code The `authCode` query parameter from the callback request.
 * @returns The signed `tra_session` token and its lifetime in seconds.
 */
export async function exchangeAuthCode(
  code: string
): Promise<{ token: string; expiresIn?: number }> {
  const response = await fetch(`${env.TRA_IDENTITY_API_URL}/auth/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code }),
    // identity-api may be reached over Railway private networking.
    allowPrivateIPAddress: true,
    timeout: 10000,
  });

  if (!response.ok) {
    throw AuthenticationError(
      `identity-api rejected the auth code (HTTP ${response.status})`
    );
  }

  const data = (await response.json()) as {
    token?: string;
    expiresIn?: number;
  };
  if (!data.token) {
    throw AuthenticationError("identity-api response did not include a token");
  }
  return { token: data.token, expiresIn: data.expiresIn };
}

/**
 * Verifies a `tra_session` JWT against identity-api's RS256 public key and
 * returns its claims.
 *
 * @param token The JWT returned by `exchangeAuthCode`.
 * @param publicKey PEM public key; defaults to `TRA_JWT_PUBLIC_KEY`.
 * @returns The verified claims.
 */
export function verifySessionToken(
  token: string,
  publicKey: string | undefined = env.TRA_JWT_PUBLIC_KEY
): TRASessionClaims {
  if (!publicKey) {
    throw AuthenticationError("TRA_JWT_PUBLIC_KEY is not configured");
  }

  const pem = publicKey.replace(/\\n/g, "\n");
  const payload = jwt.verify(token, pem, { algorithms: ["RS256"] });

  if (!payload || typeof payload !== "object") {
    throw AuthenticationError("tra_session token payload is not an object");
  }

  const { sub, email, name } = payload as Partial<TRASessionClaims>;
  if (!sub || !email || !name) {
    throw AuthenticationError(
      "tra_session token is missing the sub, email or name claim"
    );
  }

  return payload as TRASessionClaims;
}

/**
 * Whether any of the user's Entra ID groups is listed in `TRA_ADMIN_GROUPS`.
 * Matching is case-insensitive on the group display name.
 *
 * @param groups Group names from the session token.
 * @param adminGroups Comma-separated allow list; defaults to `TRA_ADMIN_GROUPS`.
 */
export function isAdminByGroups(
  groups: string[] | undefined,
  adminGroups: string = env.TRA_ADMIN_GROUPS
): boolean {
  const allowed = adminGroups
    .split(",")
    .map((group) => group.trim().toLowerCase())
    .filter(Boolean);

  if (allowed.length === 0 || !groups?.length) {
    return false;
  }

  return groups.some((group) => allowed.includes(group.toLowerCase()));
}
