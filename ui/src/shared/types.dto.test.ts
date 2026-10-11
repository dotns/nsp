import type { WgStatus } from './types';

export const wgStatusDtoExample = {
  running: false,
  interface: 'wg0',
  listen_port: 51820,
  subnet: '10.255.0.0/16',
  server_public_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  total_peers: 0,
  endpoint_host: 'proxy.example.com',
  available: true,
  reason: null,
  backend: 'kernel',
} satisfies WgStatus;
