# TRA auth plugin

Signs Outline users in through TRA's central `identity-api` (Entra ID), the same
flow every Summit app uses. Outline needs no Entra app registration of its own.

```
/auth/tra  ──►  identity-api /login?redirectUrl=<URL>/auth/tra.callback
                └─► Entra ID ─► identity-api /auth/callback ─► redirect back with ?authCode
/auth/tra.callback  ──►  POST identity-api /auth/exchange { code } ─► tra_session JWT
                         verify RS256 ─► accountProvisioner ─► signIn
```

| Variable               | Purpose                                                                                                                |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `TRA_IDENTITY_API_URL` | Public base URL of identity-api. Enables the plugin together with the key.                                             |
| `TRA_JWT_PUBLIC_KEY`   | identity-api's RS256 public key (PEM; `\n` escapes accepted). On Railway reference `${{identity-api.JWT_PUBLIC_KEY}}`. |
| `TRA_ADMIN_GROUPS`     | Optional comma-separated Entra group names promoted to Outline admin on sign-in. Never demotes.                        |

The first person to sign in creates the team and becomes its admin. Everyone
else joins as a member. identity-api must list the Outline origin in
`CORS_ORIGINS`.

Tests: `NODE_ENV=test yarn vitest run --project server plugins/tra`.
