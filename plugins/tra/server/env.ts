import { IsOptional, IsUrl } from "class-validator";
import { Environment } from "@server/env";
import environment from "@server/utils/environment";
import { CannotUseWithout } from "@server/utils/validators";

class TRAPluginEnvironment extends Environment {
  /**
   * Public base URL of TRA's identity-api, e.g. https://identity.nonprod.tmidev.net.
   * Sign-in is delegated to `${TRA_IDENTITY_API_URL}/login`, which runs the
   * Entra ID (Azure AD) flow shared by every Summit app.
   */
  @IsOptional()
  @IsUrl({ require_tld: false, allow_underscores: true })
  @CannotUseWithout("TRA_JWT_PUBLIC_KEY")
  public TRA_IDENTITY_API_URL = this.toOptionalString(
    environment.TRA_IDENTITY_API_URL
  );

  /**
   * RS256 public key (PEM) that identity-api signs `tra_session` JWTs with.
   * Literal `\n` escapes are accepted so the key can be stored on one line.
   */
  @IsOptional()
  @CannotUseWithout("TRA_IDENTITY_API_URL")
  public TRA_JWT_PUBLIC_KEY = this.toOptionalString(
    environment.TRA_JWT_PUBLIC_KEY
  );

  /**
   * Comma-separated list of Entra ID group names. Members of any listed group
   * are promoted to Outline admins when they sign in. Users are never demoted
   * automatically. Empty (default) disables group-based promotion.
   */
  public TRA_ADMIN_GROUPS = environment.TRA_ADMIN_GROUPS ?? "";
}

export default new TRAPluginEnvironment();
