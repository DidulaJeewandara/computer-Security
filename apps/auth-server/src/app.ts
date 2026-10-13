import { randomUUID } from 'node:crypto';
import type { Writable } from 'node:stream';
import Fastify from 'fastify';
import type { Config } from './config.js';
import { loadTlsOptions } from './tls.js';
import { redact, safeError, safeRequest, safeResponse } from './logging.js';
export async function buildApp(config: Config, options: { logStream?: Writable } = {}) {
  const app = Fastify({
    https: loadTlsOptions({ certFile: config.tlsCertFile, keyFile: config.tlsKeyFile }),
    requestIdHeader: false,
    genReqId: () => randomUUID(),
    bodyLimit: 64 * 1024,
    logger: {
      level: 'info',
      ...(options.logStream ? { stream: options.logStream } : {}),
      serializers: { req: safeRequest, res: safeResponse, err: safeError },
      hooks: {
        logMethod(args, method) {
          method.apply(this, args.map((arg) => redact(arg)) as typeof args);
        },
      },
    },
  });
  app.addHook('onRequest', async (request, reply) => {
    reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains');
    reply.header(
      'content-security-policy',
      "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    );
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('cache-control', 'no-store');
    reply.header('x-request-id', request.id);
    reply.header('vary', 'Origin');
    const origin = request.headers.origin;
    if (origin !== undefined && origin !== config.webOrigin) {
      return reply
        .code(403)
        .send({
          error: 'ORIGIN_REFUSED',
          message: 'Open the application from its trusted address and try again.',
        });
    }
    if (origin === config.webOrigin) {
      reply.header('access-control-allow-origin', config.webOrigin);
      reply.header('access-control-allow-credentials', 'true');
    }
  });
  app.options('/*', async (request, reply) => {
    const method = request.headers['access-control-request-method'];
    if (typeof method !== 'string' || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return reply
        .code(403)
        .send({ error: 'METHOD_REFUSED', message: 'Use an application action and try again.' });
    }
    reply.header('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE');
    reply.header('access-control-allow-headers', 'Content-Type, Authorization');
    return reply.code(204).send();
  });
  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error }, 'Request failed');
    const status =
      error.statusCode && error.statusCode >= 400 && error.statusCode < 500
        ? error.statusCode
        : 500;
    return reply
      .code(status)
      .send({
        error: 'REQUEST_FAILED',
        message: 'The request could not be completed. Please try again.',
      });
  });
  // Default Fastify 404s echo the submitted URL; use a constant safe response.
  app.setNotFoundHandler((_request, reply) =>
    reply
      .code(404)
      .send({ error: 'NOT_FOUND', message: 'Choose an available application action.' }),
  );
  app.get('/health', async () => ({ status: 'ok' }));
  return app;
}
