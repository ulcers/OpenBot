/**
 * SSH key management backed by HashiCorp Vault KV v2.
 *
 * Each key is stored at `<mount>/<prefix>/<keyName>` with fields:
 *   private_key  — the PEM-encoded private key
 *   passphrase   — optional passphrase protecting the key
 *   public_key   — optional public key for convenience
 *   fingerprint  — SHA-256 fingerprint, written on store for identification
 *
 * Reading fetches from Vault on every call so a rotation in Vault is picked up
 * without a redeploy. A short TTL cache could be added later; this is the
 * correct-by-default path.
 */

import type { VaultClient, VaultSecret } from "./client";
import type { VaultConfig } from "./config";

export type SshKeyFields = {
  private_key: string;
  passphrase?: string;
  public_key?: string;
  fingerprint?: string;
};

export type SshKeyMetadata = {
  name: string;
  version: number;
  created_time: string;
  has_passphrase: boolean;
  fingerprint?: string;
  public_key?: string;
};

export type SshKeyService = {
  store: (name: string, fields: SshKeyFields) => Promise<{ version: number }>;
  read: (name: string) => Promise<SshKeyFields | null>;
  readMetadata: (name: string) => Promise<SshKeyMetadata | null>;
  remove: (name: string) => Promise<void>;
  list: () => Promise<string[]>;
  rotate: (name: string, fields: SshKeyFields) => Promise<{ version: number }>;
  health: () => Promise<boolean>;
};

function keyPath(prefix: string, name: string): string {
  return `${prefix}/${name}`;
}

async function computeFingerprint(publicKey: string): Promise<string> {
  const clean = publicKey
    .split("\n")
    .filter(
      (line) =>
        !line.startsWith("----") && line.trim().length > 0,
    )
    .join("");

  const bytes = Buffer.from(clean, "base64");
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes),
  );
  return `SHA256:${Buffer.from(hash).toString("base64").replace(/=+$/, "")}`;
}

export function createSshKeyService(
  vault: VaultClient,
  config: VaultConfig,
): SshKeyService {
  const { mount, sshKeyPathPrefix: prefix } = config;

  return {
    async store(name, fields) {
      validateKeyName(name);
      validatePrivateKey(fields.private_key);

      const data: Record<string, string> = {
        private_key: fields.private_key,
      };
      if (fields.passphrase) {
        data.passphrase = fields.passphrase;
      }
      if (fields.public_key) {
        data.public_key = fields.public_key;
        data.fingerprint = await computeFingerprint(fields.public_key);
      }
      if (fields.fingerprint) {
        data.fingerprint = fields.fingerprint;
      }

      return vault.write(mount, keyPath(prefix, name), data);
    },

    async read(name) {
      validateKeyName(name);
      const secret = await vault.read<Record<string, string>>(
        mount,
        keyPath(prefix, name),
      );
      if (!secret) return null;
      return secretToFields(secret);
    },

    async readMetadata(name) {
      validateKeyName(name);
      const secret = await vault.read<Record<string, string>>(
        mount,
        keyPath(prefix, name),
      );
      if (!secret) return null;
      return {
        name,
        version: secret.metadata.version,
        created_time: secret.metadata.created_time,
        has_passphrase: !!secret.data.passphrase,
        fingerprint: secret.data.fingerprint,
        public_key: secret.data.public_key,
      };
    },

    async remove(name) {
      validateKeyName(name);
      await vault.delete(mount, keyPath(prefix, name));
    },

    async list() {
      try {
        const response = await fetch(
          `${config.address.replace(/\/+$/, "")}/v1/${mount}/metadata/${prefix}`,
          {
            method: "LIST",
            headers: {
              "X-Vault-Token": config.token,
              ...(config.namespace
                ? { "X-Vault-Namespace": config.namespace }
                : {}),
            },
          },
        );
        if (response.status === 404) return [];
        if (!response.ok) {
          throw new Error(
            `Vault list ${mount}/${prefix} failed: ${response.status}`,
          );
        }
        const json = (await response.json()) as {
          data: { keys: string[] };
        };
        return json.data.keys.map((key) => key.replace(/\/$/, ""));
      } catch (error) {
        if (
          error instanceof Error &&
          error.message.includes("failed")
        ) {
          throw error;
        }
        throw new Error(`Vault list failed: ${error}`);
      }
    },

    async rotate(name, fields) {
      validateKeyName(name);
      validatePrivateKey(fields.private_key);

      const data: Record<string, string> = {
        private_key: fields.private_key,
      };
      if (fields.passphrase) {
        data.passphrase = fields.passphrase;
      }
      if (fields.public_key) {
        data.public_key = fields.public_key;
        data.fingerprint = await computeFingerprint(fields.public_key);
      }
      if (fields.fingerprint) {
        data.fingerprint = fields.fingerprint;
      }

      return vault.write(mount, keyPath(prefix, name), data);
    },

    health() {
      return vault.health();
    },
  };
}

function secretToFields(
  secret: VaultSecret<Record<string, string>>,
): SshKeyFields {
  return {
    private_key: secret.data.private_key,
    ...(secret.data.passphrase ? { passphrase: secret.data.passphrase } : {}),
    ...(secret.data.public_key ? { public_key: secret.data.public_key } : {}),
    ...(secret.data.fingerprint
      ? { fingerprint: secret.data.fingerprint }
      : {}),
  };
}

function validateKeyName(name: string): void {
  if (!name || !/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `SSH key name must be alphanumeric with hyphens or underscores, got: "${name}"`,
    );
  }
}

function validatePrivateKey(key: string): void {
  if (
    !key.includes("-----BEGIN") ||
    !key.includes("PRIVATE KEY-----")
  ) {
    throw new Error("SSH key must be a PEM-encoded private key");
  }
}
