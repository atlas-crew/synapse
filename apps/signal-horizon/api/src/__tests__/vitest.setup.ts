import express from 'express';
import net from 'node:net';

type ExpressListen = typeof express.application.listen;
const originalListen = express.application.listen as ExpressListen;

const patchedExpressListen: ExpressListen = function (
  this: express.Application,
  ...args: Parameters<ExpressListen>
): ReturnType<ExpressListen> {
  if (args.length === 0) {
    return originalListen.apply(this, args);
  }

  const [port, hostOrBacklog, ...rest] = args;

  if (typeof hostOrBacklog === 'string') {
    return originalListen.call(this, port, hostOrBacklog, ...rest);
  }

  if (typeof hostOrBacklog === 'number') {
    return originalListen.call(this, port, '127.0.0.1', hostOrBacklog, ...rest);
  }

  if (typeof hostOrBacklog === 'function' || hostOrBacklog === undefined) {
    return originalListen.call(this, port, '127.0.0.1', hostOrBacklog, ...rest);
  }

  return originalListen.apply(this, args);
};

express.application.listen = patchedExpressListen;

type ServerListen = typeof net.Server.prototype.listen;
const originalServerListen = net.Server.prototype.listen as ServerListen;

const patchedServerListen: ServerListen = function (
  this: net.Server,
  ...args: Parameters<ServerListen>
): ReturnType<ServerListen> {
  if (typeof args[0] === 'number') {
    const port = args[0];
    const hostOrBacklog = args[1];

    if (typeof hostOrBacklog === 'string') {
      const host = hostOrBacklog === '0.0.0.0' ? '127.0.0.1' : hostOrBacklog;
      return originalServerListen.call(this, port, host, ...args.slice(2));
    }

    if (typeof hostOrBacklog === 'number') {
      return originalServerListen.call(this, port, '127.0.0.1', hostOrBacklog, ...args.slice(2));
    }

    if (typeof hostOrBacklog === 'function' || hostOrBacklog === undefined) {
      return originalServerListen.call(this, port, '127.0.0.1', hostOrBacklog, ...args.slice(2));
    }
  }

  return originalServerListen.apply(this, args);
};

net.Server.prototype.listen = patchedServerListen;
