import type { SecretBlock } from '@/features/users/components/secret-reveal';
import type { UserProxyEnabled, UserSsEnabled, UserWgEnabled, WgStatus } from '@/shared/types';
import { Link, useNavigate, useParams } from '@tanstack/react-router';
import { ArrowLeft, KeyRound, RefreshCw, Trash2 } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useProxyStatusQuery, useSsStatusQuery, useWgStatusQuery } from '@/features/services/api';
import {
  useDeleteUserMutation,
  useDisableUserProxyMutation,
  useDisableUserSsMutation,
  useDisableUserWgMutation,
  useEnableUserProxyMutation,
  useEnableUserSsMutation,
  useEnableUserWgMutation,
  useRotateUserProxyMutation,
  useRotateUserSsMutation,
  useRotateUserWgMutation,
  useUserProxyDetailQuery,
  useUsersQuery,
  useUserSsDetailQuery,
  useUserWgDetailQuery,
} from '@/features/users/api';
import { SecretReveal } from '@/features/users/components/secret-reveal';
import { Badge } from '@/shared/components/ui/badge';
import { Button, buttonVariants } from '@/shared/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/components/ui/card';
import { Input } from '@/shared/components/ui/input';
import { Label } from '@/shared/components/ui/label';
import { Switch } from '@/shared/components/ui/switch';
import { useToaster } from '@/shared/components/ui/toast';
import { formatBytes, formatRelativeSeconds, formatTimestamp } from '@/shared/lib/utils';

export function UserDetailPage() {
  const { name } = useParams({ from: '/_auth/users/$name' });
  const navigate = useNavigate();
  const toaster = useToaster();
  const { t } = useTranslation();
  const decoded = decodeURIComponent(name);

  const users = useUsersQuery();
  const ssStatus = useSsStatusQuery();
  const wgStatus = useWgStatusQuery();
  const proxyStatus = useProxyStatusQuery();
  const user = useMemo(() => users.data?.find((u) => u.name === decoded), [users.data, decoded]);

  const ssDetail = useUserSsDetailQuery(user?.id ?? '', { enabled: !!user?.ss_enabled });
  const wgDetail = useUserWgDetailQuery(user?.id ?? '', { enabled: !!user?.wg_enabled });
  const proxyDetail = useUserProxyDetailQuery(user?.id ?? '', {
    enabled: !!user?.proxy_enabled,
  });

  const enableSs = useEnableUserSsMutation();
  const disableSs = useDisableUserSsMutation();
  const rotateSs = useRotateUserSsMutation();
  const enableWg = useEnableUserWgMutation();
  const disableWg = useDisableUserWgMutation();
  const rotateWg = useRotateUserWgMutation();
  const enableProxy = useEnableUserProxyMutation();
  const disableProxy = useDisableUserProxyMutation();
  const rotateProxy = useRotateUserProxyMutation();
  const deleteUser = useDeleteUserMutation();
  // Two flavours of "unavailable":
  //   - absent  → driver isn't loaded at all (boot config disabled it).
  //               POST /api/users/:id/{ss,wg} returns 503; we hard-disable
  //               toggles + actions because nothing useful happens.
  //   - paused  → driver is loaded but its preconditions haven't been met
  //               (e.g. WG without CAP_NET_ADMIN). The server still accepts
  //               enable / rotate, persists the row, and reconciles into
  //               the live device once it comes up. UI keeps controls live
  //               and shows a hint instead.
  const ssAbsent = ssStatus.error?.isUnavailable() ?? false;
  const ssPaused = !ssAbsent && ssStatus.data?.available === false;
  const wgAbsent = wgStatus.error?.isUnavailable() ?? false;
  const wgPaused = !wgAbsent && wgStatus.data?.available === false;
  const proxyAbsent = proxyStatus.error?.isUnavailable() ?? false;
  // The proxy status endpoint never 503s (it returns
  // `available:false` instead, mirroring SS/WG), so use the data flag
  // as the "absent" signal. Reasoning split into discrete predicates
  // to keep the boolean precedence unambiguous.
  const proxyData = proxyStatus.data;
  const proxyDriverGone = proxyAbsent
    || (proxyData?.available === false
      && proxyData?.running === false
      && (proxyData?.reason?.includes('disabled in configuration') ?? false));
  const proxyPaused = !proxyDriverGone && proxyData?.available === false;
  const ssUnavailable = ssAbsent;
  const wgUnavailable = wgAbsent;
  const proxyUnavailable = !!proxyDriverGone;

  const [reveal, setReveal] = useState<{ title: string; blocks: SecretBlock[] } | null>(null);

  const showSs = (m: UserSsEnabled, kind: 'created' | 'rotated') => {
    const titleKey
      = kind === 'created'
        ? 'userDetail.shadowsocks.revealCreated'
        : 'userDetail.shadowsocks.revealRotated';
    setReveal({
      title: t(titleKey, { name: m.name }),
      blocks: [
        {
          label: t('userDetail.reveal.sip002'),
          value: m.url,
          filename: `${slug(m.name)}.ss.txt`,
          qrPath: `/api/users/${encodeURIComponent(m.user_id)}/ss/qr`,
        },
        {
          label: t('userDetail.reveal.psk'),
          value: m.psk,
          filename: `${slug(m.name)}.psk.txt`,
          advanced: true,
        },
        {
          label: t('userDetail.reveal.serverPsk'),
          value: m.server_psk,
          filename: `${slug(m.name)}.server-psk.txt`,
          advanced: true,
        },
      ],
    });
  };

  const showProxy = (m: UserProxyEnabled, kind: 'created' | 'rotated') => {
    const titleKey
      = kind === 'created'
        ? 'userDetail.proxy.revealCreated'
        : 'userDetail.proxy.revealRotated';
    setReveal({
      title: t(titleKey, { name: m.name }),
      blocks: [
        {
          label: t('userDetail.reveal.socks5Url'),
          value: m.socks5_url,
          filename: `${slug(m.name)}.socks5.txt`,
        },
        {
          label: t('userDetail.reveal.httpUrl'),
          value: m.http_url,
          filename: `${slug(m.name)}.http.txt`,
        },
        {
          label: t('userDetail.reveal.proxyUsername'),
          value: m.username,
          filename: `${slug(m.name)}.proxy-user.txt`,
          advanced: true,
        },
        {
          label: t('userDetail.reveal.proxyPassword'),
          value: m.password,
          filename: `${slug(m.name)}.proxy-pass.txt`,
          advanced: true,
        },
      ],
    });
  };

  const showWg = (m: UserWgEnabled, kind: 'created' | 'rotated') => {
    // conf + QR are assembled client-side so the private half, when present,
    // never leaves the browser. If the caller supplied their own public key
    // there is no `private_key`; we still render the conf + QR for the
    // public parts.
    const conf = buildClientWgConf(m, clientAllowedIps(wgStatus.data));
    const titleKey
      = kind === 'created'
        ? 'userDetail.wireguard.revealCreated'
        : 'userDetail.wireguard.revealRotated';
    const blocks: SecretBlock[] = [
      {
        label: t('userDetail.reveal.wgConf'),
        value: conf,
        filename: `${slug(m.peer.name ?? m.peer.id)}.conf`,
        qrData: conf,
      },
    ];
    if (m.secrets?.private_key) {
      blocks.push({
        label: t('userDetail.reveal.privateKey'),
        value: m.secrets.private_key,
        filename: `${slug(m.peer.name ?? m.peer.id)}.priv.txt`,
      });
    }
    setReveal({ title: t(titleKey, { name: m.peer.name ?? m.peer.id }), blocks });
  };

  if (users.isLoading) {
    return <div className="text-sm text-muted-foreground">{t('common.loading')}</div>;
  }
  if (!user) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{t('userDetail.notFoundTitle')}</CardTitle>
          <CardDescription>
            {t('userDetail.notFoundDescription', { name: decoded })}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link to="/users" className={buttonVariants({ variant: 'outline' })}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            {t('userDetail.backToUsers')}
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <div>
          <Link
            to="/users"
            className="inline-flex items-center text-xs text-muted-foreground hover:underline"
          >
            <ArrowLeft className="mr-1 h-3.5 w-3.5" />
            {t('userDetail.backToUsers')}
          </Link>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">{user.name}</h1>
          <p className="text-sm text-muted-foreground">{t('userDetail.subtitle')}</p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <ProtocolCard
          title={t('userDetail.shadowsocks.title')}
          subtitle={t('userDetail.shadowsocks.subtitle')}
          enabled={user.ss_enabled}
          metaRows={
            user.ss_enabled
              ? [
                  [t('userDetail.shadowsocks.meta.userId'), user.id],
                  [t('userDetail.shadowsocks.meta.created'), formatTimestamp(user.created_at)],
                  [t('userDetail.shadowsocks.meta.sip002'), ssDetail.data?.url ?? '—'],
                ]
              : []
          }
          actionLabel={
            user.ss_enabled
              ? t('userDetail.shadowsocks.rotate')
              : t('userDetail.shadowsocks.enable')
          }
          onToggle={(next) => {
            if (next && !user.ss_enabled) {
              enableSs.mutate(user.id, {
                onSuccess: (m) => showSs(m, 'created'),
                onError: (e) => toaster.error(t('userDetail.toasts.enableSsFailed'), e.message),
              });
            }
            else if (!next && user.ss_enabled) {
              if (!window.confirm(t('userDetail.shadowsocks.confirmDisable')))
                return;
              disableSs.mutate(user.id, {
                onError: (e) => toaster.error(t('userDetail.toasts.disableSsFailed'), e.message),
              });
            }
          }}
          onAction={() => {
            if (!user.ss_enabled)
              return;
            if (!window.confirm(t('userDetail.shadowsocks.confirmRotate')))
              return;
            rotateSs.mutate(user.id, {
              onSuccess: (m) => showSs(m, 'rotated'),
              onError: (e) => toaster.error(t('userDetail.toasts.rotateFailed'), e.message),
            });
          }}
          actionPending={enableSs.isPending || rotateSs.isPending}
          togglePending={ssUnavailable || enableSs.isPending || disableSs.isPending}
          actionDisabled={ssUnavailable}
          pausedNotice={ssPaused ? t('userDetail.paused') : undefined}
        />

        <ProtocolCard
          title={t('userDetail.wireguard.title')}
          subtitle={t('userDetail.wireguard.subtitle')}
          enabled={user.wg_enabled}
          metaRows={
            user.wg_enabled
              ? [
                  [t('userDetail.wireguard.meta.peerId'), wgDetail.data?.id ?? '—'],
                  [t('userDetail.wireguard.meta.allowedIp'), wgDetail.data?.allowed_ip ?? '—'],
                  [t('userDetail.wireguard.meta.endpoint'), wgDetail.data?.endpoint ?? '—'],
                  [t('userDetail.wireguard.meta.publicKey'), wgDetail.data?.public_key ?? '—'],
                  [
                    t('userDetail.wireguard.meta.lastHandshake'),
                    formatRelativeSeconds(wgDetail.data?.last_handshake_secs ?? null),
                  ],
                  [
                    t('userDetail.wireguard.meta.traffic'),
                    `${formatBytes(wgDetail.data?.rx_bytes ?? 0)} ↓ / ${formatBytes(wgDetail.data?.tx_bytes ?? 0)} ↑`,
                  ],
                ]
              : []
          }
          actionLabel={
            user.wg_enabled ? t('userDetail.wireguard.rotate') : t('userDetail.wireguard.enable')
          }
          onToggle={(next) => {
            if (next && !user.wg_enabled) {
              enableWg.mutate(
                { id: user.id },
                {
                  onSuccess: (m) => showWg(m, 'created'),
                  onError: (e) => toaster.error(t('userDetail.toasts.enableWgFailed'), e.message),
                },
              );
            }
            else if (!next && user.wg_enabled) {
              if (!window.confirm(t('userDetail.wireguard.confirmDisable')))
                return;
              disableWg.mutate(user.id, {
                onError: (e) => toaster.error(t('userDetail.toasts.disableWgFailed'), e.message),
              });
            }
          }}
          onAction={() => {
            if (!user.wg_enabled)
              return;
            if (!window.confirm(t('userDetail.wireguard.confirmRotate')))
              return;
            rotateWg.mutate(
              { id: user.id },
              {
                onSuccess: (m) => showWg(m, 'rotated'),
                onError: (e) => toaster.error(t('userDetail.toasts.rotateFailed'), e.message),
              },
            );
          }}
          actionPending={enableWg.isPending || rotateWg.isPending}
          togglePending={wgUnavailable || enableWg.isPending || disableWg.isPending}
          actionDisabled={wgUnavailable}
          pausedNotice={wgPaused ? t('userDetail.paused') : undefined}
        />

        <ProtocolCard
          title={t('userDetail.proxy.title')}
          subtitle={t('userDetail.proxy.subtitle')}
          enabled={user.proxy_enabled}
          metaRows={
            user.proxy_enabled
              ? [
                  [t('userDetail.proxy.meta.username'), proxyDetail.data?.username ?? '—'],
                  [t('userDetail.proxy.meta.socks5'), proxyDetail.data?.socks5_url ?? '—'],
                  [t('userDetail.proxy.meta.http'), proxyDetail.data?.http_url ?? '—'],
                ]
              : []
          }
          actionLabel={
            user.proxy_enabled ? t('userDetail.proxy.rotate') : t('userDetail.proxy.enable')
          }
          onToggle={(next) => {
            if (next && !user.proxy_enabled) {
              enableProxy.mutate(user.id, {
                onSuccess: (m) => showProxy(m, 'created'),
                onError: (e) => toaster.error(t('userDetail.toasts.enableProxyFailed'), e.message),
              });
            }
            else if (!next && user.proxy_enabled) {
              if (!window.confirm(t('userDetail.proxy.confirmDisable')))
                return;
              disableProxy.mutate(user.id, {
                onError: (e) =>
                  toaster.error(t('userDetail.toasts.disableProxyFailed'), e.message),
              });
            }
          }}
          onAction={() => {
            if (!user.proxy_enabled)
              return;
            if (!window.confirm(t('userDetail.proxy.confirmRotate')))
              return;
            rotateProxy.mutate(user.id, {
              onSuccess: (m) => showProxy(m, 'rotated'),
              onError: (e) => toaster.error(t('userDetail.toasts.rotateFailed'), e.message),
            });
          }}
          actionPending={enableProxy.isPending || rotateProxy.isPending}
          togglePending={proxyUnavailable || enableProxy.isPending || disableProxy.isPending}
          actionDisabled={proxyUnavailable}
          pausedNotice={proxyPaused ? t('userDetail.paused') : undefined}
        />
      </div>

      {!user.wg_enabled && !wgUnavailable
        ? (
            <ImportWgKeyCard
              userId={user.id}
              pending={enableWg.isPending}
              onSubmit={(public_key) =>
                enableWg.mutate(
                  { id: user.id, body: { public_key } },
                  {
                    onSuccess: (m) => showWg(m, 'created'),
                    onError: (e) => toaster.error(t('userDetail.toasts.enableWgFailed'), e.message),
                  },
                )}
            />
          )
        : null}

      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle className="text-base text-destructive">
            {t('userDetail.danger.title')}
          </CardTitle>
          <CardDescription>{t('userDetail.danger.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            variant="destructive"
            size="sm"
            disabled={deleteUser.isPending}
            onClick={() => {
              if (!window.confirm(t('userDetail.danger.confirm', { name: user.name })))
                return;
              deleteUser.mutate(user.id, {
                onSuccess: () => navigate({ to: '/users', replace: true }),
                onError: (e) => toaster.error(t('userDetail.toasts.deleteFailed'), e.message),
              });
            }}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            {t('userDetail.danger.button')}
          </Button>
        </CardContent>
      </Card>

      {reveal
        ? (
            <SecretReveal
              open
              onClose={() => setReveal(null)}
              title={reveal.title}
              blocks={reveal.blocks}
            />
          )
        : null}
    </div>
  );
}

interface ProtocolCardProps {
  title: string;
  subtitle: string;
  enabled: boolean;
  metaRows: Array<[string, string]>;
  actionLabel: string;
  onToggle: (next: boolean) => void;
  onAction: () => void;
  actionPending: boolean;
  togglePending: boolean;
  actionDisabled?: boolean;
  /**
   * Optional inline notice rendered inside the card body, e.g. when the
   * driver is loaded but its preconditions aren't yet met.
   */
  pausedNotice?: string;
}

function ProtocolCard({
  title,
  subtitle,
  enabled,
  metaRows,
  actionLabel,
  onToggle,
  onAction,
  actionPending,
  togglePending,
  actionDisabled = false,
  pausedNotice,
}: ProtocolCardProps) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <KeyRound className="h-4 w-4" />
            {title}
            {enabled
              ? (
                  <Badge variant="success">{t('common.badgeOn')}</Badge>
                )
              : (
                  <Badge variant="muted">{t('common.badgeOff')}</Badge>
                )}
          </CardTitle>
          <CardDescription>{subtitle}</CardDescription>
        </div>
        <Switch
          checked={enabled}
          onCheckedChange={onToggle}
          disabled={togglePending}
          aria-label={t('userDetail.toggleAria', { title })}
        />
      </CardHeader>
      <CardContent className="grid gap-3">
        {pausedNotice
          ? (
              <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
                {pausedNotice}
              </div>
            )
          : null}
        {metaRows.length > 0
          ? (
              <dl className="grid gap-1 text-sm">
                {metaRows.map(([k, v]) => (
                  <div key={k} className="grid grid-cols-[140px_1fr] items-baseline gap-2">
                    <dt className="text-xs uppercase tracking-wide text-muted-foreground">{k}</dt>
                    <dd className="break-all font-mono text-xs text-foreground/90">{v}</dd>
                  </div>
                ))}
              </dl>
            )
          : (
              <p className="text-sm text-muted-foreground">{t('userDetail.notEnabled')}</p>
            )}
        {enabled
          ? (
              <Button
                variant="outline"
                size="sm"
                onClick={onAction}
                disabled={actionPending || actionDisabled}
              >
                <RefreshCw className={`mr-2 h-3.5 w-3.5 ${actionPending ? 'animate-spin' : ''}`} />
                {actionPending ? t('userDetail.working') : actionLabel}
              </Button>
            )
          : null}
      </CardContent>
    </Card>
  );
}

// Validate a base64-encoded WireGuard public key. WG keys are 32 raw
// bytes, which encodes to exactly 44 base64 characters with one
// trailing `=`. Allow either standard or URL-safe alphabet so users can
// paste output from `wg pubkey`, `wg-quick`, etc. without trimming.
function isValidBase64Wgkey(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed.length !== 44 || !trimmed.endsWith('='))
    return false;
  return /^[\w+/-]{43}=$/.test(trimmed);
}

interface ImportWgKeyCardProps {
  userId: string;
  pending: boolean;
  onSubmit: (publicKey: string) => void;
}

function ImportWgKeyCard({ userId, pending, onSubmit }: ImportWgKeyCardProps) {
  const { t } = useTranslation();
  const [value, setValue] = useState('');
  const isValid = isValidBase64Wgkey(value);
  const inputId = `wg-import-${userId}`;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('userDetail.wireguard.importKey.title')}</CardTitle>
        <CardDescription>{t('userDetail.wireguard.importKey.description')}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-2">
          <Label htmlFor={inputId}>{t('userDetail.wireguard.meta.publicKey')}</Label>
          <Input
            id={inputId}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={t('userDetail.wireguard.importKey.placeholder')}
            className="font-mono"
            spellCheck={false}
            autoComplete="off"
          />
          {value && !isValid
            ? (
                <p className="text-xs text-destructive">
                  {t('userDetail.wireguard.importKey.invalid')}
                </p>
              )
            : null}
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={!isValid || pending}
          onClick={() => {
            if (!isValid)
              return;
            onSubmit(value.trim());
            setValue('');
          }}
          className="justify-self-start"
        >
          {pending ? t('userDetail.working') : t('userDetail.wireguard.importKey.submit')}
        </Button>
      </CardContent>
    </Card>
  );
}

function slug(s: string): string {
  return s.replace(/[^\w-]+/g, '_').slice(0, 64);
}

/**
 * The netstack backend has no route out of the tunnel, so its clients
 * only route the tunnel subnet; the other backends get a full tunnel.
 */
function clientAllowedIps(status: WgStatus | undefined): string {
  return status?.backend === 'netstack' && status.subnet
    ? status.subnet
    : '0.0.0.0/0, ::/0';
}

function buildClientWgConf(m: UserWgEnabled, allowedIps: string): string {
  const lines = ['[Interface]'];
  if (m.secrets?.private_key) {
    lines.push(`PrivateKey = ${m.secrets.private_key}`);
  }
  else {
    lines.push('# PrivateKey = <keep your local private key here>');
  }
  lines.push(`Address = ${m.peer.allowed_ip}`);
  lines.push('');
  lines.push('[Peer]');
  lines.push(`PublicKey = ${m.peer.public_key}`);
  if (m.secrets?.preshared_key)
    lines.push(`PresharedKey = ${m.secrets.preshared_key}`);
  lines.push(`AllowedIPs = ${allowedIps}`);
  if (m.peer.endpoint)
    lines.push(`Endpoint = ${m.peer.endpoint}`);
  if (m.peer.keepalive)
    lines.push(`PersistentKeepalive = ${m.peer.keepalive}`);
  return `${lines.join('\n')}\n`;
}

export default UserDetailPage;
