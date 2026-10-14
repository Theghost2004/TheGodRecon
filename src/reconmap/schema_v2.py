"""Additive schema 1 -> 2. Original tables and analyst decisions are preserved."""
V2_TABLES = {"tool_executions", "provider_cache", "historical_urls", "infrastructure", "technologies", "url_groups", "url_group_members", "endpoint_priority", "lineage"}
DDL = """
CREATE TABLE IF NOT EXISTS tool_executions(tool_id INTEGER PRIMARY KEY, name TEXT UNIQUE, identity_json TEXT, state TEXT, detail TEXT, started TEXT, finished TEXT, metrics_json TEXT);
CREATE TABLE IF NOT EXISTS provider_cache(key TEXT PRIMARY KEY, source TEXT, collected REAL, expires REAL, data TEXT);
CREATE TABLE IF NOT EXISTS historical_urls(identity TEXT PRIMARY KEY, url TEXT, original_url TEXT, archived_at TEXT, archive_status TEXT, mime TEXT, digest TEXT, source TEXT, allowed INTEGER, reason TEXT, collected TEXT);
CREATE TABLE IF NOT EXISTS infrastructure(host TEXT, address TEXT, asn TEXT, organization TEXT, prefix TEXT, provider_hint TEXT, confidence TEXT, source TEXT, collected TEXT, PRIMARY KEY(host,address,asn,source));
CREATE TABLE IF NOT EXISTS technologies(identity TEXT PRIMARY KEY, subject TEXT, name TEXT, version TEXT, confidence TEXT, evidence TEXT, source TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS url_groups(group_id TEXT PRIMARY KEY, signature TEXT, route_family TEXT, parameter_names TEXT, method TEXT, rule_version INTEGER);
CREATE TABLE IF NOT EXISTS url_group_members(group_id TEXT, url TEXT, source TEXT, PRIMARY KEY(group_id,url,source));
CREATE TABLE IF NOT EXISTS endpoint_priority(url TEXT PRIMARY KEY, category TEXT, score INTEGER, confidence TEXT, reasons TEXT, factors TEXT, rule_version INTEGER);
CREATE TABLE IF NOT EXISTS lineage(run_id TEXT PRIMARY KEY, parent_run_id TEXT, parent_path TEXT, kind TEXT, selected_tools TEXT, config_digest TEXT, time TEXT, reused_artifacts TEXT, metadata TEXT);
"""
