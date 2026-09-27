// Guardrails for every agent. A forbid overrides any permit.

@id("no-ssh-keys")
forbid (principal, action in [Action::"read_file", Action::"write_file", Action::"list_dir", Action::"delete_file"], resource)
when { context.path like "*/.ssh" || context.path like "*/.ssh/*" };
