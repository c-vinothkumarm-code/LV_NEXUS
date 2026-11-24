# Dynamic onboarding workflow

Every 15 minutes (and on a Pub/Sub event): discover -> compare with inventory -> register new scopes ->
validate authentication, permissions, audit logs, billing, monitoring -> derive status -> write history ->
open approval tasks for gaps -> queue a notification for new scopes -> eligible scopes
(Fully or Partially Onboarded) are picked up by collection jobs.

A scope that disappears from the provider listing becomes Inactive only when that provider's listing succeeded;
a failed listing leaves the inventory untouched. Rejected tasks are not re-opened automatically. Tasks close
themselves (`resolved`) when the related check later passes.
