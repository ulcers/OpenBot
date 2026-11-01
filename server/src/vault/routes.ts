import type { MiddlewareHandler } from "hono";
import { Hono } from "hono";
import type { AppVariables } from "../auth/guards";
import { requireAdmin } from "../auth/guards";
import type { SshKeyService } from "./ssh-keys";

export function createVaultSshKeyRoutes(
  sshKeyService: SshKeyService,
  requireUser: MiddlewareHandler<{ Variables: AppVariables }>,
) {
  const app = new Hono<{ Variables: AppVariables }>();

  app.get("/health", async (context) => {
    const healthy = await sshKeyService.health();
    return context.json({ healthy }, healthy ? 200 : 503);
  });

  app.get("/", requireUser, async (context) => {
    const denied = requireAdmin(context);
    if (denied) return denied;

    const names = await sshKeyService.list();
    const keys = await Promise.all(
      names.map((name) => sshKeyService.readMetadata(name)),
    );
    return context.json({
      keys: keys.filter((key): key is NonNullable<typeof key> => key !== null),
    });
  });

  app.get("/:name", requireUser, async (context) => {
    const denied = requireAdmin(context);
    if (denied) return denied;

    const metadata = await sshKeyService.readMetadata(
      context.req.param("name"),
    );
    if (!metadata) {
      return context.json({ error: "SSH key not found." }, 404);
    }
    return context.json({ key: metadata });
  });

  app.get("/:name/private", requireUser, async (context) => {
    const denied = requireAdmin(context);
    if (denied) return denied;

    const fields = await sshKeyService.read(context.req.param("name"));
    if (!fields) {
      return context.json({ error: "SSH key not found." }, 404);
    }
    return context.json({
      private_key: fields.private_key,
      passphrase: fields.passphrase ?? null,
    });
  });

  app.post("/", requireUser, async (context) => {
    const denied = requireAdmin(context);
    if (denied) return denied;

    const body = await context.req.json().catch(() => null);
    const parsed = parseSshKeyInput(body);
    if (!parsed) {
      return context.json({ error: "Invalid SSH key input." }, 400);
    }

    try {
      const result = await sshKeyService.store(parsed.name, {
        private_key: parsed.private_key,
        passphrase: parsed.passphrase,
        public_key: parsed.public_key,
      });
      return context.json(
        { stored: true, name: parsed.name, version: result.version },
        201,
      );
    } catch (error) {
      if (error instanceof Error) {
        return context.json({ error: error.message }, 400);
      }
      throw error;
    }
  });

  app.post("/:name/rotate", requireUser, async (context) => {
    const denied = requireAdmin(context);
    if (denied) return denied;

    const body = await context.req.json().catch(() => null);
    const parsed = parseRotateInput(body);
    if (!parsed) {
      return context.json({ error: "Invalid SSH key rotation input." }, 400);
    }

    try {
      const result = await sshKeyService.rotate(context.req.param("name"), {
        private_key: parsed.private_key,
        passphrase: parsed.passphrase,
        public_key: parsed.public_key,
      });
      return context.json({
        rotated: true,
        name: context.req.param("name"),
        version: result.version,
      });
    } catch (error) {
      if (error instanceof Error) {
        return context.json({ error: error.message }, 400);
      }
      throw error;
    }
  });

  app.delete("/:name", requireUser, async (context) => {
    const denied = requireAdmin(context);
    if (denied) return denied;

    try {
      await sshKeyService.remove(context.req.param("name"));
      return context.json({ removed: true });
    } catch (error) {
      if (error instanceof Error) {
        return context.json({ error: error.message }, 400);
      }
      throw error;
    }
  });

  return app;
}

type SshKeyInput = {
  name: string;
  private_key: string;
  passphrase?: string;
  public_key?: string;
};

function parseSshKeyInput(body: unknown): SshKeyInput | null {
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;

  const name = typeof record.name === "string" ? record.name.trim() : "";
  const privateKey =
    typeof record.private_key === "string" ? record.private_key.trim() : "";

  if (!name || !privateKey) return null;

  return {
    name,
    private_key: privateKey,
    ...(typeof record.passphrase === "string" && record.passphrase.trim()
      ? { passphrase: record.passphrase.trim() }
      : {}),
    ...(typeof record.public_key === "string" && record.public_key.trim()
      ? { public_key: record.public_key.trim() }
      : {}),
  };
}

type RotateInput = {
  private_key: string;
  passphrase?: string;
  public_key?: string;
};

function parseRotateInput(body: unknown): RotateInput | null {
  if (!body || typeof body !== "object") return null;
  const record = body as Record<string, unknown>;

  const privateKey =
    typeof record.private_key === "string" ? record.private_key.trim() : "";
  if (!privateKey) return null;

  return {
    private_key: privateKey,
    ...(typeof record.passphrase === "string" && record.passphrase.trim()
      ? { passphrase: record.passphrase.trim() }
      : {}),
    ...(typeof record.public_key === "string" && record.public_key.trim()
      ? { public_key: record.public_key.trim() }
      : {}),
  };
}
