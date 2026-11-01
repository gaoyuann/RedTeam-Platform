import { isIP } from 'node:net';

export function validUrlHostname(hostname) {
  const host = String(hostname || '').replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (isIP(host)) return true;
  return host.length > 0 && host.length <= 253 && !/^[\d.]+$/.test(host)
    && host.split('.').every(label => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label));
}
