import { Router } from 'express';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// KG data file path (relative to this source file → project root data/knowledge/)
const KG_JSON_PATH = resolve(__dirname, '../../../data/knowledge/kg_full.json');
const ZH_JSON_PATH = resolve(__dirname, '../../../data/knowledge/technique_zh.json');

// ── In-memory cache (lazy load) ──────────────────────────────────────
let _kgCache = null;

function loadKG() {
  if (!_kgCache) {
    const raw = readFileSync(KG_JSON_PATH, 'utf-8');
    _kgCache = JSON.parse(raw);
  }
  return _kgCache;
}

// ── Chinese translation maps (lazy load) ────────────────────────────
let _techniqueZhMap = null;  // key: "T1055.011" → { zh_name, zh_desc }
let _tacticZhMap = null;     // key: "TA0001" → "初始访问"

function loadZh() {
  if (_techniqueZhMap) return;
  try {
    const raw = readFileSync(ZH_JSON_PATH, 'utf-8');
    const zh = JSON.parse(raw);
    _techniqueZhMap = new Map();
    _tacticZhMap = new Map();
    for (const [mitreId, info] of Object.entries(zh)) {
      _techniqueZhMap.set(mitreId, { zh_name: info.zh_name || '', zh_desc: info.zh_desc || '' });
      if (info.tactic_id && info.zh_tactic) {
        _tacticZhMap.set(info.tactic_id, info.zh_tactic);
      }
    }
  } catch {
    _techniqueZhMap = new Map();
    _tacticZhMap = new Map();
  }
}

// ── Tool name Chinese mapping ───────────────────────────────────────
const TOOL_ZH_NAMES = {
  nmap_scan: 'Nmap扫描', nuclei_scan: 'Nuclei扫描', gobuster_scan: 'Gobuster目录扫描',
  hydra_brute: 'Hydra暴力破解', sqlmap_scan: 'SQLMap注入检测', nikto_scan: 'Nikto Web扫描',
  wpscan_scan: 'WPScan WordPress扫描', smbclient_enum: 'SMB枚举', crackmapexec: 'CrackMapExec',
  ldapsearch_enum: 'LDAP搜索枚举', enum4linux_scan: 'Enum4Linux枚举', dig_enum: 'Dig DNS枚举',
  whois_enum: 'Whois查询', ping_scan: 'Ping探测', traceroute_scan: '路由追踪',
  prowler_scan: 'Prowler云安全扫描', trivy_scan: 'Trivy容器扫描', ffuf_fuzz: 'FFUF模糊测试',
  dirsearch_scan: 'Dirsearch目录扫描', medusa_brute: 'Medusa暴力破解', wfuzz_fuzz: 'Wfuzz模糊测试',
  skipfish_scan: 'Skipfish扫描', arachni_scan: 'Arachni扫描', whatweb_enum: 'WhatWeb识别',
  dnsrecon_enum: 'DNSRecon枚举', dmitry_enum: 'DMitry信息收集', theharvester_enum: 'TheHarvester收集',
  fierce_enum: 'Fierce DNS枚举', rpcclient_enum: 'RPC枚举', net_enum: 'Net枚举',
  wmi_exec: 'WMI执行', psexec_exec: 'PsExec执行', smbexec_exec: 'SmbExec执行',
  atexec_exec: 'AtExec执行', mssqlclient_exec: 'MSSQL客户端执行',
  shodan_enum: 'Shodan搜索', censys_enum: 'Censys搜索',
  patator_brute: 'Patator暴力破解', hashcat_crack: 'Hashcat破解', john_crack: 'John破解',
  searchsploit_lookup: 'SearchSploit查询', msf_exploit: 'Metasploit利用',
  impacket_exec: 'Impacket执行',Responder_spoof: 'Responder欺骗',
};

/**
 * Inject zh_name / zh_desc into a node object based on its type and id.
 * Returns a new object with zh_name and zh_desc added.
 */
function injectZh(node) {
  loadZh();
  const result = { ...node, zh_name: '', zh_desc: '' };
  const type = node.type;

  if (type === 'AttackTechnique') {
    // Extract MITRE ID from node id like "technique:T1055.011"
    const mitreId = node.id.replace('technique:', '');
    const zh = _techniqueZhMap.get(mitreId);
    if (zh) {
      result.zh_name = zh.zh_name;
      result.zh_desc = zh.zh_desc;
    }
  } else if (type === 'AttackTactic') {
    // Extract tactic ID from node id like "tactic:TA0001"
    const tacticId = node.id.replace('tactic:', '');
    const zhName = _tacticZhMap.get(tacticId);
    if (zhName) result.zh_name = zhName;
  } else if (type === 'HexToolWrapper') {
    // Use tool name mapping
    const toolKey = node.id.replace('wrapper:', '');
    if (TOOL_ZH_NAMES[toolKey]) result.zh_name = TOOL_ZH_NAMES[toolKey];
  }
  // HexPayload already has Chinese names in kg_full.json
  // Other types (AttackGroup, AttackSoftware, AttackMitigation, etc.) — no translation, keep English

  return result;
}

/**
 * Get Chinese name for a node by its id and type (for edge display).
 */
function getZhName(nodeId, nodeType) {
  if (!nodeId) return '';
  loadZh();
  if (nodeType === 'AttackTechnique') {
    const mitreId = nodeId.replace('technique:', '');
    const zh = _techniqueZhMap.get(mitreId);
    return zh?.zh_name || '';
  } else if (nodeType === 'AttackTactic') {
    const tacticId = nodeId.replace('tactic:', '');
    return _tacticZhMap.get(tacticId) || '';
  } else if (nodeType === 'HexToolWrapper') {
    const toolKey = nodeId.replace('wrapper:', '');
    return TOOL_ZH_NAMES[toolKey] || '';
  }
  return '';
}

// ── Build lookup maps on first load ──────────────────────────────────
let _nodeMap = null;
let _nameMap = null;

function buildLookups() {
  if (_nodeMap) return;
  const kg = loadKG();
  _nodeMap = new Map();
  _nameMap = new Map();
  for (const node of kg.nodes) {
    _nodeMap.set(node.id, node);
    if (node.name) _nameMap.set(node.name, node);
  }
}

export default function (db) {
  const router = Router();

  // ── GET /stats ────────────────────────────────────────────────────
  router.get('/stats', (_req, res) => {
    try {
      const kg = loadKG();
      const meta = kg.metadata || {};
      res.json({
        status: 'ok',
        data: {
          node_count: kg.nodes.length,
          edge_count: kg.edges.length,
          kg_version: meta.version || '1.0.0',
          generated_at: meta.generated_at || '',
          node_type_counts: meta.node_type_counts || {},
          edge_type_counts: meta.edge_type_counts || {},
          source_systems: meta.source_systems || [],
          safety: meta.safety || {},
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /graph ────────────────────────────────────────────────────
  // Optional query: ?types=HexToolWrapper,AttackTechnique  ?limit=300
  router.get('/graph', (req, res) => {
    try {
      const kg = loadKG();
      const typesParam = req.query.types;
      const limit = parseInt(req.query.limit) || 0;
      let nodes = kg.nodes;
      let edges = kg.edges;

      if (typesParam) {
        const allowedTypes = new Set(typesParam.split(',').map(t => t.trim()));
        nodes = nodes.filter(n => allowedTypes.has(n.type));
        const nodeIds = new Set(nodes.map(n => n.id));
        edges = edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
      }

      // Apply node limit — keep most-connected nodes first
      if (limit > 0 && nodes.length > limit) {
        // Count degree for each node
        const degree = new Map();
        for (const e of edges) {
          degree.set(e.source, (degree.get(e.source) || 0) + 1);
          degree.set(e.target, (degree.get(e.target) || 0) + 1);
        }
        // Sort by degree descending, take top N
        nodes.sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0));
        nodes = nodes.slice(0, limit);
        // Filter edges to only those between kept nodes
        const keptIds = new Set(nodes.map(n => n.id));
        edges = edges.filter(e => keptIds.has(e.source) && keptIds.has(e.target));
      }

      res.json({
        status: 'ok',
        data: {
          metadata: kg.metadata,
          nodes: nodes.map(injectZh),
          edges,
          total_node_count: kg.nodes.length,
          total_edge_count: kg.edges.length,
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /node/:id ────────────────────────────────────────────────
  router.get('/node/:id', (req, res) => {
    try {
      buildLookups();
      const nodeId = req.params.id;
      const node = _nodeMap.get(nodeId);
      if (!node) {
        // Try prefix-based lookup
        const prefixed = ['wrapper:', 'technique:', 'tactic:', 'group:', 'software:', 'mitigation:', 'endpoint:', 'payload:'];
        for (const prefix of prefixed) {
          const candidate = _nodeMap.get(prefix + nodeId);
          if (candidate) {
            return res.json({ status: 'ok', data: buildNodeDetail(candidate) });
          }
        }
        return res.status(404).json({ status: 'error', error: { message: 'Node not found' } });
      }
      res.json({ status: 'ok', data: buildNodeDetail(node) });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /mappings ────────────────────────────────────────────────
  // Returns MAPS_TO_TECHNIQUE edges with resolved source/target names
  router.get('/mappings', (req, res) => {
    try {
      buildLookups();
      const kg = loadKG();
      const confidence = req.query.confidence;
      const limit = Math.min(parseInt(req.query.limit) || 500, 1000);
      const offset = parseInt(req.query.offset) || 0;

      let mappings = kg.edges
        .filter(e => e.type === 'MAPS_TO_TECHNIQUE')
        .map(e => {
          const srcNode = _nodeMap.get(e.source);
          const tgtNode = _nodeMap.get(e.target);
          return {
            edge_id: e.id,
            source_id: e.source,
            source_name: srcNode?.name || e.source,
            source_zh_name: srcNode ? getZhName(srcNode.id, srcNode.type) : '',
            source_type: srcNode?.type || '',
            target_id: e.target,
            target_name: tgtNode?.name || e.target,
            target_zh_name: tgtNode ? getZhName(tgtNode.id, tgtNode.type) : '',
            target_external_id: tgtNode?.source_ref || '',
            confidence: e.confidence || '',
            mapping_rationale: e.mapping_rationale || '',
            import_status: e.import_status || '',
          };
        });

      if (confidence) {
        mappings = mappings.filter(m => m.confidence === confidence);
      }

      const total = mappings.length;
      mappings = mappings.slice(offset, offset + limit);

      res.json({ status: 'ok', data: { total, limit, offset, mappings } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /tactics ─────────────────────────────────────────────────
  router.get('/tactics', (_req, res) => {
    try {
      const kg = loadKG();
      const tactics = kg.nodes
        .filter(n => n.type === 'AttackTactic')
        .map(n => {
          const zh = injectZh(n);
          return {
            id: n.id,
            name: n.name,
            zh_name: zh.zh_name,
            source_ref: n.source_ref || '',
            description: (n.description || '').substring(0, 200),
            short_name: n.short_name || n.name,
          };
        });
      res.json({ status: 'ok', data: { count: tactics.length, tactics } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /techniques ──────────────────────────────────────────────
  // Optional: ?tactic=TA0001  ?limit=50  ?offset=0
  router.get('/techniques', (req, res) => {
    try {
      const kg = loadKG();
      const tacticFilter = req.query.tactic;
      const limit = Math.min(parseInt(req.query.limit) || 100, 500);
      const offset = parseInt(req.query.offset) || 0;

      let techniques = kg.nodes.filter(n => n.type === 'AttackTechnique');

      if (tacticFilter) {
        // Find techniques connected to this tactic via BELONGS_TO_TACTIC
        const tacticId = tacticFilter.startsWith('tactic:') ? tacticFilter : `tactic:${tacticFilter}`;
        const connectedIds = new Set(
          kg.edges
            .filter(e => e.type === 'BELONGS_TO_TACTIC' && e.target === tacticId)
            .map(e => e.source)
        );
        techniques = techniques.filter(n => connectedIds.has(n.id));
      }

      const total = techniques.length;
      techniques = techniques.slice(offset, offset + limit).map(n => {
        const zh = injectZh(n);
        return {
          id: n.id,
          external_id: n.source_ref || n.id.replace('technique:', ''),
          name: n.name,
          zh_name: zh.zh_name,
          zh_desc: zh.zh_desc,
          is_subtechnique: n.is_subtechnique || false,
          description: (n.description || '').substring(0, 200),
        };
      });

      res.json({ status: 'ok', data: { total, limit, offset, techniques } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /search?q=... ────────────────────────────────────────────
  router.get('/search', (req, res) => {
    try {
      const kg = loadKG();
      const q = (req.query.q || '').toLowerCase();
      const typeFilter = req.query.type;
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);

      if (!q) {
        return res.json({ status: 'ok', data: { total: 0, results: [] } });
      }

      let results = kg.nodes.filter(n => {
        if (typeFilter && n.type !== typeFilter) return false;
        return (
          (n.id || '').toLowerCase().includes(q) ||
          (n.name || '').toLowerCase().includes(q) ||
          (n.description || '').toLowerCase().includes(q)
        );
      });

      const total = results.length;
      results = results.slice(0, limit).map(n => {
        const zh = injectZh(n);
        return {
          id: n.id,
          name: n.name,
          zh_name: zh.zh_name,
          zh_desc: zh.zh_desc,
          type: n.type,
          source_system: n.source_system || '',
          risk_level: n.risk_level_candidate || '',
          description: (n.description || '').substring(0, 150),
        };
      });

      res.json({ status: 'ok', data: { total, results } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Candidate Mappings routes ──────────────────────────────────────────
  createCandidateMappingRoutes(router, db);

  return router;
}

// ── Candidate Mappings routes (use db directly) ──────────────────────────

/**
 * POST /candidate-mappings/approve/:id — Approve a candidate mapping
 * POST /candidate-mappings/reject/:id — Reject a candidate mapping
 * These are mounted on the router above. We define them inline to access `db`.
 */

// Helper to create candidate-mapping sub-routes that share the db reference
function createCandidateMappingRoutes(router, db) {
  // GET /candidate-mappings — List candidate mappings with optional status filter
  router.get('/candidate-mappings', (req, res) => {
    try {
      const { status, run_id, limit, offset } = req.query;
      let sql = 'SELECT * FROM candidate_mappings WHERE 1=1';
      const params = [];
      if (status) { sql += ' AND status = ?'; params.push(status); }
      if (run_id) { sql += ' AND run_id = ?'; params.push(run_id); }
      sql += ' ORDER BY confidence DESC';
      if (limit) { sql += ' LIMIT ?'; params.push(Number(limit)); }
      if (offset) { sql += ' OFFSET ?'; params.push(Number(offset)); }
      const rows = db.prepare(sql).all(...params);
      res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // POST /candidate-mappings/:id/approve — Approve a candidate mapping
  router.post('/candidate-mappings/:id/approve', (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM candidate_mappings WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ status: 'error', error: { message: 'Candidate mapping not found' } });
      db.prepare("UPDATE candidate_mappings SET status = 'approved' WHERE id = ?").run(req.params.id);
      const updated = db.prepare('SELECT * FROM candidate_mappings WHERE id = ?').get(req.params.id);
      res.json({ status: 'ok', data: updated });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // POST /candidate-mappings/:id/reject — Reject a candidate mapping
  router.post('/candidate-mappings/:id/reject', (req, res) => {
    try {
      const row = db.prepare('SELECT * FROM candidate_mappings WHERE id = ?').get(req.params.id);
      if (!row) return res.status(404).json({ status: 'error', error: { message: 'Candidate mapping not found' } });
      db.prepare("UPDATE candidate_mappings SET status = 'rejected' WHERE id = ?").run(req.params.id);
      const updated = db.prepare('SELECT * FROM candidate_mappings WHERE id = ?').get(req.params.id);
      res.json({ status: 'ok', data: updated });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });
}

// ── Helper: build node detail with connected edges ───────────────────
function buildNodeDetail(node) {
  const kg = loadKG();
  const outEdges = kg.edges
    .filter(e => e.source === node.id)
    .map(e => ({
      edge_id: e.id, type: e.type, target_id: e.target,
      target_name: _nodeMap.get(e.target)?.name || e.target,
      target_type: _nodeMap.get(e.target)?.type || '',
      confidence: e.confidence || '',
    }));
  const inEdges = kg.edges
    .filter(e => e.target === node.id)
    .map(e => ({
      edge_id: e.id, type: e.type, source_id: e.source,
      source_name: _nodeMap.get(e.source)?.name || e.source,
      source_type: _nodeMap.get(e.source)?.type || '',
      confidence: e.confidence || '',
    }));
  const zhNode = injectZh(node);
  return {
    node: {
      id: zhNode.id, type: zhNode.type, name: zhNode.name,
      zh_name: zhNode.zh_name, zh_desc: zhNode.zh_desc,
      source_system: zhNode.source_system || '',
      description: zhNode.description || '',
      import_status: zhNode.import_status || '',
      risk_level: zhNode.risk_level_candidate || '',
      metadata: zhNode.metadata || {},
    },
    out_edges: outEdges.map(e => ({ ...e, target_zh_name: getZhName(e.target_id, e.target_type) })),
    in_edges: inEdges.map(e => ({ ...e, source_zh_name: getZhName(e.source_id, e.source_type) })),
    out_edge_count: outEdges.length,
    in_edge_count: inEdges.length,
  };
}
