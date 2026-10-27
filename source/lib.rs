//! Rajacek API core.
//!
//! This crate contains the HTTP API, security boundaries, provider abstraction, rate-limit
//! implementation, and asynchronous usage-event handoff used by the Rajacek platform.

pub mod admin_roles;
pub mod alerts;
pub mod analytics;
pub mod api;
pub mod auth;
pub mod bank_codes;
pub mod blog;
pub mod config;
pub mod database;
pub mod error;
pub mod events;
pub mod ewallet_codes;
pub mod idempotency;
pub mod member;
pub mod models;
pub mod provider;
pub mod provider_config;
pub mod provider_guard;
pub mod qris;
pub mod rate_limit;
pub mod session_revocation;
pub mod store;
