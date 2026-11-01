/**
 * Vault configuration, read from the environment at boot.
 *
 * All three variables are required when any one is set, and absent when none is.
 * The mount and SSH key path have defaults so a deployment only has to set the
 * address and token to start storing SSH keys in Vault.
 */

export type VaultConfig = {
  address: string;
  token: string;
  namespace?: string;
  /** KV v2 mount point. Defaults to "secret". */
  mount: string;
  /** Path prefix under the mount for SSH keys. Defaults to "openbot/ssh-keys". */
  sshKeyPathPrefix: string;
};

type Environment = Record<string, string | undefined>;

function optional(environment: Environment, name: string): string | undefined {
  return environment[name]?.trim() || undefined;
}

export function vaultConfig(environment: Environment): VaultConfig | undefined {
  const address = optional(environment, "VAULT_ADDR");
  const token = optional(environment, "VAULT_TOKEN");

  if (!address && !token) return undefined;

  if (!address || !token) {
    throw new Error(
      "VAULT_ADDR and VAULT_TOKEN must both be set when either is present.",
    );
  }

  return {
    address,
    token,
    namespace: optional(environment, "VAULT_NAMESPACE"),
    mount: optional(environment, "VAULT_KV_MOUNT") ?? "secret",
    sshKeyPathPrefix:
      optional(environment, "VAULT_SSH_KEY_PATH_PREFIX") ?? "openbot/ssh-keys",
  };
}
