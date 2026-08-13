import { readdirSync, existsSync } from 'fs';
import { exec as execCb } from 'child_process';
import { promisify } from 'util';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const execAsync = promisify(execCb);
const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');

export async function ensureImagesLoaded(engine) {
  if (engine === 'host') return;

  const tarDir = resolve(PROJECT_ROOT, 'containers', 'tar');
  if (!existsSync(tarDir)) {
    console.log('[ImageLoader] No tar directory found, skipping auto-load');
    return;
  }

  // Get currently loaded images
  let localImages = [];
  try {
    const { stdout } = await execAsync(`${engine} images --format '{{.Repository}}'`, { timeout: 10000 });
    localImages = stdout.trim().split('\n').filter(l => l);
  } catch {
    console.log('[ImageLoader] Cannot list images, skipping auto-load');
    return;
  }

  const tarFiles = readdirSync(tarDir).filter(f => f.endsWith('.tar')).sort();

  for (const tar of tarFiles) {
    const imageName = tar.replace('.tar', '');
    if (localImages.includes(imageName)) {
      console.log(`[ImageLoader] ${imageName} already loaded`);
      continue;
    }
    console.log(`[ImageLoader] Loading ${tar}...`);
    try {
      await execAsync(`${engine} load -i ${join(tarDir, tar)}`, { timeout: 120_000 });
      console.log(`[ImageLoader] Loaded ${imageName}`);
    } catch (err) {
      console.error(`[ImageLoader] Failed to load ${tar}: ${err.message}`);
    }
  }
}
