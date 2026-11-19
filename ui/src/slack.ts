// Builds Slack app manifests so an owner can create a custom app in one step.
// Slack's app page accepts a manifest in the URL and opens it in its create-app flow.

export type SlackAccess = "read" | "write";

// Presets that take a token from a custom Slack app.
export const SLACK_APP_PRESETS = ["slack", "slack_socket_mode"];

export const SLACK_APP_NAME = "Perimeter agent";
const MAX_NAME = 35;

const READ_SCOPES = [
  "bookmarks:read",
  "channels:history",
  "channels:read",
  "emoji:read",
  "files:read",
  "groups:history",
  "groups:read",
  "im:history",
  "im:read",
  "mpim:history",
  "mpim:read",
  "pins:read",
  "reactions:read",
  "team:read",
  "usergroups:read",
  "users:read",
];
const WRITE_SCOPES = [
  "bookmarks:write",
  "channels:join",
  "chat:write",
  "files:write",
  "im:write",
  "pins:write",
  "reactions:write",
];
// Socket Mode delivers mentions and direct messages; replying needs chat:write.
const SOCKET_SCOPES = ["app_mentions:read", "chat:write", "im:history"];
const SOCKET_EVENTS = ["app_mention", "message.im"];

export const slackScopes = (preset: string, access: SlackAccess) =>
  preset === "slack_socket_mode"
    ? [...SOCKET_SCOPES]
    : [...READ_SCOPES, ...(access === "write" ? WRITE_SCOPES : [])].sort();

// Slack limits app and bot names to 35 characters and refuses blank ones.
export const slackAppName = (name: string) =>
  name.trim().replace(/\s+/g, " ").slice(0, MAX_NAME).trim() || SLACK_APP_NAME;

export function slackManifest(
  preset: string,
  name: string,
  access: SlackAccess,
) {
  const title = slackAppName(name);
  const socket = preset === "slack_socket_mode";
  return {
    display_information: {
      name: title,
      description: "Lets your agents use Slack through Tinfoil Perimeter.",
    },
    features: {
      bot_user: { display_name: title, always_online: false },
      ...(socket
        ? {
            app_home: {
              messages_tab_enabled: true,
              messages_tab_read_only_enabled: false,
            },
          }
        : {}),
    },
    oauth_config: { scopes: { bot: slackScopes(preset, access) } },
    settings: {
      ...(socket ? { event_subscriptions: { bot_events: SOCKET_EVENTS } } : {}),
      org_deploy_enabled: false,
      socket_mode_enabled: socket,
      token_rotation_enabled: false,
    },
  };
}

// GovSlack apps are managed on its own API host.
export const slackAppsOrigin = (origin?: string) =>
  origin?.replace(/\/+$/, "") === "https://slack-gov.com"
    ? "https://api.slack-gov.com"
    : "https://api.slack.com";

export const slackCreateURL = (
  preset: string,
  name: string,
  access: SlackAccess,
  origin?: string,
) =>
  `${slackAppsOrigin(origin)}/apps?new_app=1&manifest_json=${encodeURIComponent(
    JSON.stringify(slackManifest(preset, name, access)),
  )}`;

// What to do in Slack after the app exists, ending with the token this preset needs.
export const slackSteps = (preset: string) =>
  preset === "slack_socket_mode"
    ? [
        "Choose your workspace and select Create.",
        "In Basic Information, under App-Level Tokens, generate a token with the connections:write scope.",
        "Install the app to your workspace, then paste the xapp- token below.",
      ]
    : [
        "Choose your workspace and select Create.",
        "Select Install to Workspace and allow the requested access.",
        "In OAuth & Permissions, copy the Bot User OAuth Token (xoxb-) and paste it below.",
      ];
