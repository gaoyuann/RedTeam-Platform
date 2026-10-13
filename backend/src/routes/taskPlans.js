import { Router } from 'express';
import { getTaskPlan, getTaskPlanSources, createTaskPlan, saveTaskPlan, addTaskPlanSuggestion, transitionTaskPlan } from '../services/taskPlan.js';

export default function taskPlanRoutes(db, loadResume = async () => (await import('../services/pipelineEngine.js')).resumePipelineAfterApproval) {
  const router = Router({ mergeParams: true });
  router.use((req, res, next) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
    if (req.user.role !== 'admin' && pipeline.created_by !== req.user.sub)
      return res.status(403).json({ status: 'error', error: { message: '没有权限访问此任务预案' } });
    next();
  });
  router.get('/', (req, res) => res.json({ status: 'ok', data: getTaskPlan(db, req.params.id) }));
  router.get('/sources', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(req.params.id);
    res.json({status:'ok', data:getTaskPlanSources(db, pipeline, req.user)});
  });
  const mutate = (action, operation) => async (req, res, next) => {
    try {
      const resume = action === 'approve' ? await loadResume() : null;
      const data = db.transaction(() => {
        const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
        if (!pipeline) throw Object.assign(new Error('任务已删除'), { status: 404 });
        if (req.user.role !== 'admin' && pipeline.created_by !== req.user.sub)
          throw Object.assign(new Error('没有权限修改此任务预案'), { status: 403 });
        return operation(pipeline, req.user, req.body || {});
      })();
      if (resume) {
        Promise.resolve().then(() => resume(req.params.id)).then(result => {
          if (result?.ok === false) throw new Error(result.error || 'Execution did not start');
        }).catch(err => {
          console.error(`[TaskPlan] Resume failed for ${req.params.id}:`, err.message);
          db.prepare("UPDATE pipelines SET status = 'failed', error_message = '审批后执行启动异常', updated_at = datetime('now') WHERE pipeline_id = ? AND status IN ('awaiting_approval', 'running')")
            .run(req.params.id);
        });
      }
      res.status(resume ? 202 : 200).json({ status: 'ok', data });
    } catch (error) {
      if (error.status) return res.status(error.status).json({ status: 'error', error: { message: error.message } });
      next(error);
    }
  };
  router.post('/', mutate('create', (pipeline, actor, body) => createTaskPlan(db, pipeline, actor, body.playbook_id)));
  router.put('/', mutate('save', (pipeline, actor, body) => saveTaskPlan(db, pipeline, actor, body)));
  router.post('/suggestions', mutate('suggestion', (pipeline, actor, body) => addTaskPlanSuggestion(db, pipeline, actor, body)));
  for (const action of ['submit', 'reopen', 'reject', 'approve'])
    router.post(`/${action}`, mutate(action, (pipeline, actor, body) => transitionTaskPlan(db, pipeline, actor, action, body)));
  return router;
}
