// research-bot: a research assistant that works inside /workspace.
// Cedar denies by default; each permit below opens one narrow path.

@id("files-read-workspace")
permit (
  principal == Agent::"research-bot",
  action in [Action::"read_file", Action::"list_dir"],
  resource
)
when { context.path == "/workspace" || context.path like "/workspace/*" };

@id("files-write-workspace")
permit (principal == Agent::"research-bot", action == Action::"write_file", resource)
when { context.path like "/workspace/*" };

// Deletes are limited to scratch space.
@id("files-delete-scratch")
permit (principal == Agent::"research-bot", action == Action::"delete_file", resource)
when { context.path like "/workspace/tmp/*" };

// Any http(s) fetch. Phase 4 adds an egress allowlist and result scanning.
@id("web-fetch-http")
permit (principal == Agent::"research-bot", action == Action::"fetch_url", resource)
when { ["http", "https"].contains(context.url_scheme) };

// Email only to internal domains.
@id("email-internal-only")
permit (principal == Agent::"research-bot", action == Action::"send_email", resource)
when { ["lab.test"].contains(context.recipient_domain) };

@id("weather-lookup")
permit (principal == Agent::"research-bot", action == Action::"get_weather", resource);
