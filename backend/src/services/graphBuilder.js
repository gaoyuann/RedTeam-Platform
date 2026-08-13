/**
 * GraphBuilder - Constructs visualizable attack graph
 * Ported from RedTeam-Edu: backend/src/runs/graphBuilder.js
 */

/**
 * Build attack graph from findings and interventions.
 *
 * @param {object} params
 * @param {string} params.target - target host/network
 * @param {Array} params.findings - evidence records from DB
 * @param {Array} params.interventions - blue team interventions
 * @returns {{ version: string, target: string, nodes: Array, edges: Array }}
 */
export function buildAttackGraph({ target, findings = [], interventions = [] }) {
  const nodes = [];
  const edges = [];
  const nodeSet = new Set();

  // 1. Create Host node (always present)
  const hostNodeId = `host:${target || 'unknown'}`;
  nodes.push({
    id: hostNodeId,
    type: 'host',
    label: target || 'unknown',
    group: 'target',
    properties: { findingsCount: findings.length },
  });
  nodeSet.add(hostNodeId);

  // 2. Process findings to create service/webpath nodes
  for (const finding of findings) {
    const evidenceType = finding.evidence_type || 'tool_output';
    const toolId = finding.tool_id || '';
    const data = parseEvidenceData(finding.evidence_data);

    switch (evidenceType) {
      case 'open_port': {
        const port = data.port || '?';
        const service = data.service || toolId;
        const proto = data.protocol || 'tcp';
        const nodeId = `service:${target}:${port}`;

        if (!nodeSet.has(nodeId)) {
          nodes.push({
            id: nodeId,
            type: 'service',
            label: `${port}/${proto} (${service})`,
            group: 'service',
            properties: { port, service, proto },
          });
          nodeSet.add(nodeId);
        }

        // Edge: host → service
        const edgeId = `edge:host_to_service:${target}:${port}`;
        if (!edges.find(e => e.id === edgeId)) {
          edges.push({
            id: edgeId,
            source: hostNodeId,
            target: nodeId,
            type: 'has_port',
            label: `${port}/${proto}`,
          });
        }
        break;
      }

      case 'web_fingerprint': {
        const techName = data.technology || data.server || 'unknown';
        const nodeId = `tech:${target}:${techName}`;

        if (!nodeSet.has(nodeId)) {
          nodes.push({
            id: nodeId,
            type: 'technology',
            label: techName,
            group: 'technology',
            properties: { source: toolId },
          });
          nodeSet.add(nodeId);
        }

        const edgeId = `edge:host_to_tech:${target}:${techName}`;
        if (!edges.find(e => e.id === edgeId)) {
          edges.push({
            id: edgeId,
            source: hostNodeId,
            target: nodeId,
            type: 'runs',
            label: toolId,
          });
        }
        break;
      }

      case 'dir_enum':
      case 'fuzz_result': {
        const path = data.path || data.url || '/';
        const nodeId = `path:${target}:${path}`;

        if (!nodeSet.has(nodeId)) {
          nodes.push({
            id: nodeId,
            type: 'web_path',
            label: path,
            group: 'webpath',
            properties: { status: data.status || 200 },
          });
          nodeSet.add(nodeId);
        }

        // Find the relevant service node (or use host)
        const svcId = `service:${target}:80`;
        const sourceId = nodeSet.has(svcId) ? svcId : hostNodeId;

        const edgeId = `edge:svc_to_path:${target}:${path}`;
        if (!edges.find(e => e.id === edgeId)) {
          edges.push({
            id: edgeId,
            source: sourceId,
            target: nodeId,
            type: 'has_path',
            label: toolId,
          });
        }
        break;
      }

      case 'vulnerability': {
        const vulnName = data.name || data.title || 'CVE-unknown';
        const severity = data.severity || 'medium';
        const nodeId = `vuln:${target}:${vulnName.replace(/\s+/g, '_')}`;

        if (!nodeSet.has(nodeId)) {
          nodes.push({
            id: nodeId,
            type: 'vulnerability',
            label: vulnName,
            group: 'vuln',
            properties: { severity, source: toolId },
          });
          nodeSet.add(nodeId);
        }

        const edgeId = `edge:to_vuln:${target}:${vulnName}`;
        if (!edges.find(e => e.id === edgeId)) {
          edges.push({
            id: edgeId,
            source: hostNodeId,
            target: nodeId,
            type: 'has_vulnerability',
            label: severity,
          });
        }
        break;
      }

      case 'credential_access': {
        const credType = data.type || 'password';
        const nodeId = `cred:${target}:${credType}`;

        if (!nodeSet.has(nodeId)) {
          nodes.push({
            id: nodeId,
            type: 'credential',
            label: `${credType} obtained`,
            group: 'credential',
            properties: { source: toolId },
          });
          nodeSet.add(nodeId);
        }

        const edgeId = `edge:to_cred:${target}:${credType}`;
        if (!edges.find(e => e.id === edgeId)) {
          edges.push({
            id: edgeId,
            source: hostNodeId,
            target: nodeId,
            type: 'compromised',
            label: toolId,
          });
        }
        break;
      }

      default:
        // Generic finding node
        const nodeId = `finding:${target}:${toolId}:${finding.step_index || 0}`;
        if (!nodeSet.has(nodeId)) {
          nodes.push({
            id: nodeId,
            type: 'finding',
            label: `${toolId} output`,
            group: 'finding',
            properties: { evidenceType },
          });
          nodeSet.add(nodeId);

          edges.push({
            id: `edge:to_finding:${nodeId}`,
            source: hostNodeId,
            target: nodeId,
            type: 'produced',
            label: toolId,
          });
        }
    }
  }

  // 3. Apply intervention mitigations
  for (const intervention of interventions) {
    const intNodeId = `mitigation:${intervention.id || intervention.type}`;

    if (!nodeSet.has(intNodeId)) {
      nodes.push({
        id: intNodeId,
        type: 'mitigation',
        label: `Mitigation: ${intervention.type}`,
        group: 'mitigation',
        properties: {
          interventionType: intervention.type,
          target: intervention.target,
          port: intervention.port,
          path: intervention.path,
        },
      });
      nodeSet.add(intNodeId);
    }

    // Connect mitigation to the host
    const edgeId = `edge:mitigation_to_host:${intNodeId}`;
    if (!edges.find(e => e.id === edgeId)) {
      edges.push({
        id: edgeId,
        source: intNodeId,
        target: hostNodeId,
        type: 'mitigates',
        label: intervention.type,
        dashed: true,
      });
    }

    // If intervention blocks a port, find and mark that service node
    if (intervention.type === 'block_port' && intervention.port) {
      const svcNodeId = `service:${target}:${intervention.port}`;
      const svcNode = nodes.find(n => n.id === svcNodeId);
      if (svcNode) {
        svcNode.properties = { ...svcNode.properties, mitigated: true };
      }
    }

    if (intervention.type === 'block_path' && intervention.path) {
      const pathNodeId = `path:${target}:${intervention.path}`;
      const pathNode = nodes.find(n => n.id === pathNodeId);
      if (pathNode) {
        pathNode.properties = { ...pathNode.properties, mitigated: true };
      }
    }
  }

  return {
    version: '1.0',
    target: target || 'unknown',
    nodes,
    edges,
    stats: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      hostCount: nodes.filter(n => n.type === 'host').length,
      serviceCount: nodes.filter(n => n.type === 'service').length,
      vulnCount: nodes.filter(n => n.type === 'vulnerability').length,
      mitigationCount: nodes.filter(n => n.type === 'mitigation').length,
    },
  };
}

/**
 * Parse evidence_data JSON string with error handling.
 */
function parseEvidenceData(data) {
  if (!data) return {};
  if (typeof data === 'object') return data;
  try {
    return JSON.parse(data);
  } catch {
    return { raw: data.substring(0, 200) };
  }
}

/**
 * Build a simplified text summary of the attack graph for display.
 */
export function buildAttackGraphSummary(graph) {
  const lines = [];
  lines.push(`攻击图: ${graph.target}`);
  lines.push(`节点: ${graph.stats.totalNodes}, 边: ${graph.stats.totalEdges}`);

  const hostNode = graph.nodes.find(n => n.type === 'host');
  if (hostNode) {
    const services = graph.edges.filter(e => e.type === 'has_port').map(e => {
      const svc = graph.nodes.find(n => n.id === e.target);
      return svc ? svc.label : e.label;
    });
    if (services.length > 0) {
      lines.push(`服务: ${services.join(', ')}`);
    }

    const vulns = graph.edges.filter(e => e.type === 'has_vulnerability').map(e => {
      const v = graph.nodes.find(n => n.id === e.target);
      return v ? `${v.label} (${e.label})` : e.label;
    });
    if (vulns.length > 0) {
      lines.push(`漏洞: ${vulns.join(', ')}`);
    }

    const mitigations = graph.nodes.filter(n => n.type === 'mitigation');
    if (mitigations.length > 0) {
      lines.push(`防御措施: ${mitigations.map(m => m.properties.interventionType).join(', ')}`);
    }
  }

  return lines.join('\n');
}
