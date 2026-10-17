"""Additive graph cache. Raw evidence and analyst decisions remain authoritative."""
V4_TABLES = {'graph_nodes', 'graph_edges'}
DDL = '''
CREATE TABLE IF NOT EXISTS graph_nodes(id TEXT PRIMARY KEY, type TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS graph_edges(id TEXT PRIMARY KEY, source TEXT NOT NULL, destination TEXT NOT NULL, type TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS graph_edge_source ON graph_edges(source);
CREATE INDEX IF NOT EXISTS graph_edge_destination ON graph_edges(destination);
'''
