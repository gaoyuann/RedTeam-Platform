import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DEFAULT_SOURCE = resolve(
  __dirname, '..', '..', '..', '..', '..',
  'RedTeam-Edu', 'hexstrike-edu', 'backend', 'config', 'model_config.json'
);

export default function up(db) {
  const sourcePath = process.env.MODEL_CONFIG_PATH || DEFAULT_SOURCE;
  let raw;
  try {
    raw = JSON.parse(readFileSync(sourcePath, 'utf-8'));
  } catch {
    console.log(`[Migration 004] Source not found: ${sourcePath}, skipping`);
    return;
  }

  const insert = db.prepare(`
    INSERT OR IGNORE INTO system_config (config_key, config_value, category, description)
    VALUES (?, ?, 'llm', ?)
  `);

  const tx = db.transaction(() => {
    let count = 0;
    for (const [key, value] of Object.entries(raw)) {
      insert.run(key, JSON.stringify(value), `LLM model: ${key}`);
      count++;
    }
    console.log(`[Migration 004] Imported ${count} LLM config entries`);
  });

  tx();
}
