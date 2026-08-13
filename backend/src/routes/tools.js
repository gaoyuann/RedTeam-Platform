import { Router } from 'express';
import { runTool, IMAGE_MAP, VIRTUAL_TOOLS } from '../tools/toolRunner.js';
import { getEngine } from '../tools/containerEngine.js';
import { exec as execCb } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(execCb);

export default function (db) {
  const router = Router();

  // ── Execute a tool ──────────────────────────────────────────────────
  router.post('/execute', async (req, res) => {
    const { toolId, args, timeout, maxOutputKB } = req.body;
    if (!toolId) return res.status(400).json({ status: 'error', error: { message: 'toolId is required' } });

    try {
      const result = await runTool(toolId, args || [], { timeout, maxOutputKB });
      res.json({ status: 'ok', data: result });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Container engine status ─────────────────────────────────────────
  router.get('/containers/status', async (_req, res) => {
    try {
      const engine = await getEngine();
      let engineVersion = null;
      let images = [];
      const imageSizes = {};

      if (engine !== 'host') {
        try {
          const { stdout } = await execAsync(`${engine} version --format '{{.Server.Version}}'`, { timeout: 5000 });
          engineVersion = stdout.trim();
        } catch {}

        try {
          // Get images with size info
          const { stdout } = await execAsync(
            `${engine} images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}'`,
            { timeout: 5000 }
          );
          const lines = stdout.trim().split('\n').filter(l => l && !l.includes('<none>'));
          for (const line of lines) {
            const [repoTag, size] = line.split('\t');
            if (repoTag) {
              images.push(repoTag);
              if (size) imageSizes[repoTag] = size;
            }
          }
        } catch {}
      }

      const expectedImages = [...new Set(Object.values(IMAGE_MAP))].map(name => `${name}:latest`);
      const loadedImages = expectedImages.filter(e => images.includes(e));

      res.json({
        status: 'ok',
        data: {
          engine,
          engineVersion,
          images: images.filter(i => i.startsWith('rt-')),
          imageSizes,
          expectedImages,
          loadedCount: loadedImages.length,
          expectedCount: expectedImages.length,
          allLoaded: loadedImages.length === expectedImages.length,
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Tool list ───────────────────────────────────────────────────────
  router.get('/list', (_req, res) => {
    const tools = Object.entries(IMAGE_MAP).map(([toolId, image]) => ({
      toolId,
      image,
      virtual: VIRTUAL_TOOLS.has(toolId),
    }));
    // Add virtual tools
    for (const v of VIRTUAL_TOOLS) {
      tools.push({ toolId: v, image: null, virtual: true });
    }
    res.json({ status: 'ok', data: tools, meta: { total: tools.length } });
  });

  return router;
}
