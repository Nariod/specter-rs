//! Command handlers (port of `src_beacon/src/tasks/`): files, process,
//! tokens, SOCKS5, port forwarding, screenshot, jobs. Dispatch is typed and
//! exhaustive: a command the server can send without a matching handler is a
//! compilation error, not a silent `default:` branch.
//!
//! Phase 3 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).
