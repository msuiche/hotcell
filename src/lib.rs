pub mod cli;
pub mod events;
#[cfg(feature = "live")]
pub mod live;
pub mod renderer;
pub mod report;
pub mod static_scan;
pub mod targets;

pub const DEFAULT_RULES: &str = include_str!("../assets/default.yaml");
pub const AGENT_SOURCE: &str = include_str!("../assets/hotcell_agent.js");
