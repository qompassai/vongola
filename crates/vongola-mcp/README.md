# vongola-mcp

Read-only, operator-local stdio MCP server over a running vongola daemon's admin surfaces.

mcp-name: ai.qompass/vongola

Vongola is Qompass AI's reverse proxy and web server — a clean-room rewrite on Pingora. This crate is its operator instrumentation companion: it exposes the daemon's admin surfaces to MCP clients as read-only tools, with no mutation path.
