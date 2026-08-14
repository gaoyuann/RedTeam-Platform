import { readFileSync, readdirSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Prefer data/playbooks/ inside this project (always available after git clone),
// fallback to RedTeam-Edu for local dev convenience.
const PROJECT_PLAYBOOKS_DIR = resolve(__dirname, '..', '..', '..', 'data', 'playbooks');
const DEFAULT_PLAYBOOKS_DIR = existsSync(PROJECT_PLAYBOOKS_DIR)
  ? PROJECT_PLAYBOOKS_DIR
  : resolve(__dirname, '..', '..', '..', '..', '..', 'RedTeam-Edu', 'hexstrike-edu', 'backend', 'config', 'playbooks');

const PROJECT_GENERATED_DIR = resolve(__dirname, '..', '..', '..', 'data', 'generated_playbooks');
const DEFAULT_GENERATED_DIR = existsSync(PROJECT_GENERATED_DIR)
  ? PROJECT_GENERATED_DIR
  : resolve(__dirname, '..', '..', '..', '..', '..', 'RedTeam-Edu', 'hexstrike-edu', 'backend', 'logs', 'generated_playbooks');

const KNOWN_COLUMNS = new Set([
  'id', 'name', 'description', 'author', 'difficulty', 'category',
  'estimatedMinutes', 'estimatedTimeMinutes', 'targetType', 'notSuitableFor',
  'baselineGroup', 'expectedOutputPolicy', 'teachingObjective',
  'rolesAllowed', 'disableAutoInsert', 'enableKGContext',
  'requiresTeacherReview', 'mitreTechniques', 'steps'
]);

function extractPlaybookRow(pb, isGenerated) {
  const metadata = {};
  for (const [k, v] of Object.entries(pb)) {
    if (!KNOWN_COLUMNS.has(k) && k !== 'steps') {
      metadata[k] = v;
    }
  }

  return {
    playbook_id: pb.id,
    name: pb.name,
    description: pb.description || null,
    author: pb.author || null,
    difficulty: pb.difficulty || null,
    category: pb.category || null,
    estimated_time: pb.estimatedTimeMinutes || pb.estimatedMinutes || null,
    target_type: pb.targetType ? JSON.stringify(pb.targetType) : null,
    not_suitable_for: pb.notSuitableFor ? JSON.stringify(pb.notSuitableFor) : null,
    baseline_group: pb.baselineGroup || null,
    expected_output_policy: pb.expectedOutputPolicy || null,
    teaching_objective: pb.teachingObjective || null,
    roles_allowed: pb.rolesAllowed ? JSON.stringify(pb.rolesAllowed) : null,
    disable_auto_insert: pb.disableAutoInsert ? 1 : 0,
    enable_kg_context: pb.enableKGContext ? 1 : 0,
    requires_teacher_review: pb.requiresTeacherReview ? 1 : 0,
    mitre_techniques: pb.mitreTechniques ? JSON.stringify(pb.mitreTechniques) : null,
    metadata: Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : null,
    is_generated: isGenerated ? 1 : 0,
    generated_from: isGenerated ? 'imported' : null,
    generated_at: isGenerated ? new Date().toISOString() : null,
  };
}

export default function up(db) {
  const playbooksDir = process.env.PLAYBOOKS_DIR || DEFAULT_PLAYBOOKS_DIR;
  const generatedDir = process.env.GENERATED_PLAYBOOKS_DIR || DEFAULT_GENERATED_DIR;

  const insertPb = db.prepare(`
    INSERT OR IGNORE INTO playbooks (
      playbook_id, name, description, author, difficulty, category,
      estimated_time, target_type, not_suitable_for, baseline_group,
      expected_output_policy, teaching_objective, roles_allowed,
      disable_auto_insert, enable_kg_context, requires_teacher_review,
      mitre_techniques, metadata, is_generated, generated_from, generated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertStep = db.prepare(`
    INSERT OR IGNORE INTO playbook_steps (
      playbook_id, step_index, step_id, name, tool_id, args_template,
      description, score, expected_mitre, payload_id, payload_variables,
      evidence_config, requires_teacher_review, optional
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  function importDirectory(dir, isGenerated) {
    let files;
    try {
      files = readdirSync(dir).filter(f => f.endsWith('.json')).sort();
    } catch {
      console.log(`[Migration 003] Directory not found: ${dir}, skipping`);
      return 0;
    }

    let count = 0;
    const tx = db.transaction(() => {
      for (const file of files) {
        const pb = JSON.parse(readFileSync(join(dir, file), 'utf-8'));
        const row = extractPlaybookRow(pb, isGenerated);

        insertPb.run(
          row.playbook_id, row.name, row.description, row.author,
          row.difficulty, row.category, row.estimated_time, row.target_type,
          row.not_suitable_for, row.baseline_group, row.expected_output_policy,
          row.teaching_objective, row.roles_allowed, row.disable_auto_insert,
          row.enable_kg_context, row.requires_teacher_review, row.mitre_techniques,
          row.metadata, row.is_generated, row.generated_from, row.generated_at
        );

        const steps = pb.steps || [];
        for (let i = 0; i < steps.length; i++) {
          const s = steps[i];
          insertStep.run(
            pb.id, i, s.id, s.name, s.toolId,
            s.argsTemplate ? JSON.stringify(s.argsTemplate) : null,
            s.description || null,
            s.score || 0,
            s.expectedMitre ? JSON.stringify(s.expectedMitre) : null,
            s.payload_id || null,
            s.payload_variables ? JSON.stringify(s.payload_variables) : null,
            s.evidence ? JSON.stringify(s.evidence) : null,
            s.requiresTeacherReview ? 1 : 0,
            s.optional ? 1 : 0
          );
        }
        count++;
      }
    });
    tx();
    return count;
  }

  const staticCount = importDirectory(playbooksDir, false);
  console.log(`[Migration 003] Imported ${staticCount} static playbooks`);

  const genCount = importDirectory(generatedDir, true);
  console.log(`[Migration 003] Imported ${genCount} generated playbooks`);
}
