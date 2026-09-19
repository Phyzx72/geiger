// Shared logic for the many places MCP server configs live.
import { readJson, readText } from '../util/fsx.js';
import { assessMcpServer } from '../engine.js';
import { scanEnvObject, scanText } from '../redact.js';

const DECLARES_AGENT_SURFACE = /"(mcpServers|servers|context_servers|mcp|hooks|apiKeyHelper)"\s*:/;

/**
 * A config that exists but cannot be parsed is still a finding, never a
 * silent skip: it is shape-scanned for credentials like any partially
 * parseable format, and says when it appears to declare servers or hooks.
 * `error` is the location-only label from parseJsonTolerant — no content.
 */
export function unparseableFinding(file, detector, hostLabel, error) {
  const text = readText(file) || '';
  const shapes = scanText(text);
  const notes = ['file exists but could not be parsed — review it by hand'];
  if (DECLARES_AGENT_SURFACE.test(text)) {
    notes.push('it appears to declare MCP servers or hooks; they are not reported individually until the file parses');
  }
  return {
    detector, kind: 'config', name: `unparseable config (${hostLabel})`,
    origin: { type: 'local', ref: file },
    exposures: shapes.length ? ['HOLDS-SECRETS'] : [],
    evidence: [{ file, note: error }],
    secrets: shapes.map((shape) => ({ key: '(in unparseable config text)', shape, file })),
    confidence: 'low',
    notes,
  };
}

/**
 * Read a JSON config file and emit one finding per entry under `mcpServers`
 * (or a custom key). Returns [] when the file is absent; emits a
 * low-confidence config finding when present but unparseable.
 */
export function findingsFromMcpFile(file, detector, hostLabel, key = 'mcpServers') {
  const { value, error } = readJson(file);
  if (error === 'missing') return [];
  if (error) return [unparseableFinding(file, detector, hostLabel, error)];
  const servers = (value && value[key]) || {};
  const out = [];
  for (const [name, server] of Object.entries(servers)) {
    const f = assessMcpServer(name, server, file, detector, hostLabel);
    const hits = scanEnvObject(server && server.env);
    if (hits.length) {
      f.exposures = [...new Set([...f.exposures, 'HOLDS-SECRETS'])];
      f.secrets = hits.map((h) => ({ ...h, file }));
    }
    out.push(f);
  }
  return out;
}
