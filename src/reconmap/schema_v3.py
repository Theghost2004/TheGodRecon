"""Additive 2 -> 3 migration. Derived views never replace original evidence."""
V3_TABLES = {"stage_results", "normalized_records", "investigation_candidates"}
DDL = """
CREATE TABLE IF NOT EXISTS stage_results(name TEXT PRIMARY KEY, result_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS normalized_records(identity TEXT PRIMARY KEY, url TEXT NOT NULL, method TEXT NOT NULL, context TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS investigation_candidates(identity TEXT PRIMARY KEY, url TEXT NOT NULL, category TEXT, score INTEGER, tier TEXT, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS normalized_url ON normalized_records(url);
CREATE INDEX IF NOT EXISTS candidate_rank ON investigation_candidates(tier, score);
"""
