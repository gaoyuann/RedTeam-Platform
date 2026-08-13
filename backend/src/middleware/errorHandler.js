export default function errorHandler(err, _req, res, _next) {
  console.error('[Error]', err.message || err);
  const status = err.status || 500;
  res.status(status).json({
    status: 'error',
    error: {
      message: err.message || 'Internal server error',
      code: err.code || 'INTERNAL_ERROR',
    },
  });
}
