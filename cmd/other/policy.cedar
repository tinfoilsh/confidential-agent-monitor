// Engineers open SSH and HTTPS to staging hosts.
permit (principal in Group::"engineering", action == Action::"connect", resource)
when { resource.environment == "staging" && [22, 443].contains(context.port) };

// Engineers read production databases. Only the on-call rotation writes to them.
permit (principal in Group::"engineering", action in [Action::"connect", Action::"read"], resource)
when { resource.environment == "production" };

permit (principal in Group::"oncall", action == Action::"write", resource)
when { resource.environment == "production" };

// A contractor's other groups never reach production.
forbid (principal in Group::"contractors", action, resource)
when { resource.environment == "production" };
