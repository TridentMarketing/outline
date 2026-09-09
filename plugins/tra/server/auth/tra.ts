import type { Context } from "koa";
import Router from "koa-router";
import { Client, UserRole } from "@shared/types";
import { slugifyDomain } from "@shared/utils/domains";
import { parseEmail } from "@shared/utils/email";
import { toError } from "@shared/utils/error";
import accountProvisioner from "@server/commands/accountProvisioner";
import { createContext } from "@server/context";
import Logger from "@server/logging/Logger";
import { signIn } from "@server/utils/authentication";
import { getTeamFromContext, startOAuthFlow } from "@server/utils/passport";
import config from "../../plugin.json";
import env from "../env";
import {
  exchangeAuthCode,
  isAdminByGroups,
  verifySessionToken,
} from "../identity";

const router = new Router();

/**
 * Sign-in flow, mirroring how every TRA Summit app authenticates:
 *
 *   1. GET /auth/tra           -> redirect to identity-api /login?redirectUrl=<callback>
 *   2. identity-api            -> Entra ID (Azure AD) OIDC, issues a tra_session JWT
 *   3. GET /auth/tra.callback  -> ?authCode=<one-time code>
 *   4. POST identity-api /auth/exchange { code } -> { token }
 *   5. verify RS256 signature, provision the Outline user + team, sign in
 *
 * identity-api owns the Entra app registration, so Outline needs no client id,
 * secret or redirect URI of its own — only the public key to verify tokens.
 */
router.get(config.id, startOAuthFlow, async (ctx: Context) => {
  const login = new URL("/login", env.TRA_IDENTITY_API_URL);
  login.searchParams.set(
    "redirectUrl",
    `${env.URL}/auth/${config.id}.callback`
  );
  ctx.redirect(login.toString());
});

router.get(`${config.id}.callback`, async (ctx: Context) => {
  const authCode = ctx.query.authCode;

  if (typeof authCode !== "string" || !authCode) {
    Logger.warn("TRA sign-in callback received without an authCode");
    return ctx.redirect("/?notice=auth-error");
  }

  try {
    const { token, expiresIn } = await exchangeAuthCode(authCode);
    const claims = verifySessionToken(token);

    const email = claims.email.toLowerCase();
    const { domain } = parseEmail(email);
    const team = await getTeamFromContext(ctx);
    const identityHost = new URL(env.TRA_IDENTITY_API_URL!).hostname;

    const result = await accountProvisioner(createContext({ ip: ctx.ip }), {
      team: {
        teamId: team?.id,
        name: env.APP_NAME,
        domain,
        subdomain: slugifyDomain(domain),
      },
      user: {
        name: claims.name,
        email,
        // The email comes from the Entra directory via identity-api.
        emailVerified: true,
      },
      authenticationProvider: {
        name: config.id,
        providerId: identityHost,
      },
      authentication: {
        providerId: claims.sub,
        accessToken: token,
        expiresIn,
        scopes: [],
      },
    });

    if (isAdminByGroups(claims.groups) && result.user.role !== UserRole.Admin) {
      await result.user.update({ role: UserRole.Admin });
      Logger.info(
        "authentication",
        `Promoted ${email} to admin via TRA_ADMIN_GROUPS`
      );
    }

    return signIn(ctx, config.id, { ...result, client: Client.Web });
  } catch (err) {
    Logger.error("TRA sign-in failed", toError(err));
    return ctx.redirect("/?notice=auth-error");
  }
});

export default router;
