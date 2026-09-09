import { Hook, PluginManager } from "@server/utils/PluginManager";
import config from "../plugin.json";
import router from "./auth/tra";
import env from "./env";

const enabled = !!env.TRA_IDENTITY_API_URL && !!env.TRA_JWT_PUBLIC_KEY;

if (enabled) {
  PluginManager.add({
    ...config,
    type: Hook.AuthProvider,
    value: { router, id: config.id },
  });
}
