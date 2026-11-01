/**
 * Thin HTTP client for the HashiCorp Vault KV v2 secrets engine.
 *
 * Every read returns the current version so a caller can tell whether a secret
 * changed between two reads without holding the plaintext in memory.
 */

export type VaultClientConfig = {
  address: string;
  token: string;
  namespace?: string;
};

export type VaultSecret<T = Record<string, string>> = {
  data: T;
  metadata: { version: number; created_time: string; destroyed: boolean };
};

export type VaultClient = {
  read: <T = Record<string, string>>(
    mount: string,
    path: string,
  ) => Promise<VaultSecret<T> | null>;
  write: <T = Record<string, string>>(
    mount: string,
    path: string,
    data: T,
  ) => Promise<{ version: number }>;
  delete: (mount: string, path: string) => Promise<void>;
  health: () => Promise<boolean>;
};

export function createVaultClient(config: VaultClientConfig): VaultClient {
  const headers: Record<string, string> = {
    "X-Vault-Token": config.token,
    "Content-Type": "application/json",
  };
  if (config.namespace) {
    headers["X-Vault-Namespace"] = config.namespace;
  }

  const base = config.address.replace(/\/+$/, "");

  async function request(
    method: string,
    url: string,
    body?: unknown,
  ): Promise<Response> {
    const response = await fetch(url, {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return response;
  }

  return {
    async read<T = Record<string, string>>(mount: string, path: string) {
      const response = await request(
        "GET",
        `${base}/v1/${mount}/data/${path}`,
      );
      if (response.status === 404) return null;
      if (!response.ok) {
        throw new Error(
          `Vault read ${mount}/${path} failed: ${response.status} ${response.statusText}`,
        );
      }
      const json = (await response.json()) as {
        data: { data: T; metadata: VaultSecret<T>["metadata"] };
      };
      return { data: json.data.data, metadata: json.data.metadata };
    },

    async write<T = Record<string, string>>(
      mount: string,
      path: string,
      data: T,
    ) {
      const response = await request(
        "POST",
        `${base}/v1/${mount}/data/${path}`,
        { data },
      );
      if (!response.ok) {
        throw new Error(
          `Vault write ${mount}/${path} failed: ${response.status} ${response.statusText}`,
        );
      }
      const json = (await response.json()) as {
        data: { version: number };
      };
      return { version: json.data.version };
    },

    async delete(mount: string, path: string) {
      const response = await request(
        "DELETE",
        `${base}/v1/${mount}/metadata/${path}`,
      );
      if (!response.ok && response.status !== 404) {
        throw new Error(
          `Vault delete ${mount}/${path} failed: ${response.status} ${response.statusText}`,
        );
      }
    },

    async health() {
      try {
        const response = await request("GET", `${base}/v1/sys/health`);
        return response.ok || response.status === 429 || response.status === 473;
      } catch {
        return false;
      }
    },
  };
}
