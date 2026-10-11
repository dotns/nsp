import type { FormEvent } from 'react';
import type { SecretBlock } from '@/features/users/components/secret-reveal';
import type { UserEntry, UserProxyEnabled, UserSsEnabled, UserWgEnabled, WgStatus } from '@/shared/types';
import { Link } from '@tanstack/react-router';
import { ChevronLeft, ChevronRight, KeyRound, Plus, Search, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useProxyStatusQuery, useSsStatusQuery, useWgStatusQuery } from '@/features/services/api';
import {
  useCreateUserMutation,
  useDeleteUserMutation,
  useDisableUserProxyMutation,
  useDisableUserSsMutation,
  useDisableUserWgMutation,
  useEnableUserProxyMutation,
  useEnableUserSsMutation,
  useEnableUserWgMutation,
  useUsersQuery,
} from '@/features/users/api';
import { SecretReveal } from '@/features/users/components/secret-reveal';
import { Button, buttonVariants } from '@/shared/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/shared/components/ui/dialog';
import { Input } from '@/shared/components/ui/input';
import { Label } from '@/shared/components/ui/label';
import { Switch } from '@/shared/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/shared/components/ui/table';
import { useToaster } from '@/shared/components/ui/toast';
import { ApiError } from '@/shared/lib/http';
import { formatTimestamp } from '@/shared/lib/utils';

const PAGE_SIZE = 10;

export function UsersPage() {
  const toaster = useToaster();
  const { t } = useTranslation();
  const users = useUsersQuery();
  const ssStatus = useSsStatusQuery();
  const wgStatus = useWgStatusQuery();
  const proxyStatus = useProxyStatusQuery();
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [reveal, setReveal] = useState<{ title: string; blocks: SecretBlock[] } | null>(null);

  const enableSs = useEnableUserSsMutation();
  const disableSs = useDisableUserSsMutation();
  const enableWg = useEnableUserWgMutation();
  const disableWg = useDisableUserWgMutation();
  const enableProxy = useEnableUserProxyMutation();
  const disableProxy = useDisableUserProxyMutation();
  const deleteUser = useDeleteUserMutation();

  // Two flavours of "unavailable" — see user-detail-page.tsx for the
  // full rationale. We only hard-disable controls when the driver is
  // absent; if it is merely paused (preconditions not met), the API
  // still accepts enables and reconciles them once the driver comes
  // back, so the UI keeps the toggle live.
  const ssAbsent = ssStatus.error?.isUnavailable() ?? false;
  const ssPaused = !ssAbsent && ssStatus.data?.available === false;
  const wgAbsent = wgStatus.error?.isUnavailable() ?? false;
  const wgPaused = !wgAbsent && wgStatus.data?.available === false;
  // The proxy status route never 503s (it returns 200 with
  // `available:false` when the driver is absent), so treat the
  // "disabled in configuration" reason as the absent signal and any
  // other `available:false` as paused.
  const proxyAvailableFlag = proxyStatus.data?.available ?? true;
  const proxyConfigDisabled = !proxyAvailableFlag
    && proxyStatus.data?.reason?.toLowerCase().includes('disabled in configuration');
  const proxyAbsent = (proxyStatus.error?.isUnavailable() ?? false) || !!proxyConfigDisabled;
  const proxyPaused = !proxyAbsent && !proxyAvailableFlag;
  const ssDriverDown = ssAbsent;
  const wgDriverDown = wgAbsent;
  const proxyDriverDown = proxyAbsent;

  const rows = useMemo<UserEntry[]>(() => {
    return [...(users.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  }, [users.data]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q)
      return rows;
    return rows.filter((r) => r.name.toLowerCase().includes(q));
  }, [rows, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const visible = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  const handleToggleSs = (row: UserEntry, next: boolean) => {
    if (next && !row.ss_enabled) {
      enableSs.mutate(row.id, {
        onSuccess: (m) => showSsCreated(m),
        onError: (err) => toaster.error(t('users.toasts.enableSsFailed'), err.message),
      });
    }
    else if (!next && row.ss_enabled) {
      disableSs.mutate(row.id, {
        onError: (err) => toaster.error(t('users.toasts.disableSsFailed'), err.message),
      });
    }
  };

  const handleToggleWg = (row: UserEntry, next: boolean) => {
    if (next && !row.wg_enabled) {
      enableWg.mutate(
        { id: row.id },
        {
          onSuccess: (m) => showWgCreated(m),
          onError: (err) => toaster.error(t('users.toasts.enableWgFailed'), err.message),
        },
      );
    }
    else if (!next && row.wg_enabled) {
      disableWg.mutate(row.id, {
        onError: (err) => toaster.error(t('users.toasts.disableWgFailed'), err.message),
      });
    }
  };

  const handleToggleProxy = (row: UserEntry, next: boolean) => {
    if (next && !row.proxy_enabled) {
      enableProxy.mutate(row.id, {
        onSuccess: (m) => showProxyCreated(m),
        onError: (err) => toaster.error(t('users.toasts.enableProxyFailed'), err.message),
      });
    }
    else if (!next && row.proxy_enabled) {
      disableProxy.mutate(row.id, {
        onError: (err) => toaster.error(t('users.toasts.disableProxyFailed'), err.message),
      });
    }
  };

  const handleDelete = (row: UserEntry) => {
    if (!window.confirm(t('users.confirmRemove', { name: row.name })))
      return;
    deleteUser.mutate(row.id, {
      onError: (err) => toaster.error(t('users.toasts.deleteFailed'), err.message),
    });
  };

  const showSsCreated = (m: UserSsEnabled) => {
    setReveal({
      title: t('users.reveal.ssTitle', { name: m.name }),
      blocks: [
        {
          label: t('users.reveal.sip002Label'),
          value: m.url,
          filename: `${slug(m.name)}.ss.txt`,
          qrPath: `/api/users/${encodeURIComponent(m.user_id)}/ss/qr`,
        },
        {
          label: t('users.reveal.pskLabel'),
          value: m.psk,
          filename: `${slug(m.name)}.psk.txt`,
          advanced: true,
        },
        {
          label: t('users.reveal.serverPskLabel'),
          value: m.server_psk,
          filename: `${slug(m.name)}.server-psk.txt`,
          advanced: true,
        },
      ],
    });
  };

  const showProxyCreated = (m: UserProxyEnabled) => {
    setReveal({
      title: t('users.reveal.proxyTitle', { name: m.name }),
      blocks: [
        {
          label: t('users.reveal.socks5UrlLabel'),
          value: m.socks5_url,
          filename: `${slug(m.name)}.socks5.txt`,
        },
        {
          label: t('users.reveal.httpUrlLabel'),
          value: m.http_url,
          filename: `${slug(m.name)}.http.txt`,
        },
        {
          label: t('users.reveal.proxyUsernameLabel'),
          value: m.username,
          filename: `${slug(m.name)}.proxy-user.txt`,
          advanced: true,
        },
        {
          label: t('users.reveal.proxyPasswordLabel'),
          value: m.password,
          filename: `${slug(m.name)}.proxy-pass.txt`,
          advanced: true,
        },
      ],
    });
  };

  const showWgCreated = (m: UserWgEnabled) => {
    // The server never stores the client private key. The conf + QR are
    // assembled here so secrets do not leave the browser. If the caller
    // supplied their own public key there will be no `private_key` —
    // the UI still shows conf + public fields.
    const conf = buildClientWgConf(m, clientAllowedIps(wgStatus.data));
    const blocks: SecretBlock[] = [
      {
        label: t('users.reveal.wgConfLabel'),
        value: conf,
        filename: `${slug(m.peer.name ?? m.peer.id)}.conf`,
        qrData: conf,
      },
    ];
    if (m.secrets?.private_key) {
      blocks.push({
        label: t('users.reveal.privateKeyLabel'),
        value: m.secrets.private_key,
        filename: `${slug(m.peer.name ?? m.peer.id)}.priv.txt`,
      });
    }
    setReveal({
      title: t('users.reveal.wgTitle', { name: m.peer.name ?? m.peer.id }),
      blocks,
    });
  };

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t('users.heading')}</h1>
          <p className="text-sm text-muted-foreground">{t('users.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          {t('users.newUser')}
        </Button>
      </div>

      <div className="flex items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder={t('users.searchPlaceholder')}
            className="pl-8"
            aria-label={t('users.searchAria')}
          />
        </div>
        <span className="text-xs text-muted-foreground">
          {filtered.length === 1
            ? t('users.countOne', { count: filtered.length })
            : t('users.countOther', { count: filtered.length })}
        </span>
      </div>

      <div className="rounded-md border border-border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('users.table.name')}</TableHead>
              <TableHead>{t('users.table.ss')}</TableHead>
              <TableHead>{t('users.table.wg')}</TableHead>
              <TableHead>{t('users.table.proxy')}</TableHead>
              <TableHead>{t('users.table.created')}</TableHead>
              <TableHead className="text-right">{t('users.table.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.isLoading
              ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      {t('common.loading')}
                    </TableCell>
                  </TableRow>
                )
              : visible.length === 0
                ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        {search ? t('users.emptyFiltered') : t('users.empty')}
                      </TableCell>
                    </TableRow>
                  )
                : (
                    visible.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="font-medium">
                          <Link to="/users/$name" params={{ name: row.name }} className="hover:underline">
                            {row.name}
                          </Link>
                          {row.note
                            ? (
                                <div className="mt-0.5 text-xs text-muted-foreground">{row.note}</div>
                              )
                            : null}
                        </TableCell>
                        <TableCell>
                          <Switch
                            checked={row.ss_enabled}
                            disabled={
                              ssDriverDown
                              || enableSs.isPending
                              || disableSs.isPending
                              || deleteUser.isPending
                            }
                            onCheckedChange={(c) => handleToggleSs(row, c)}
                            aria-label={t('users.toggleSsAria', { name: row.name })}
                          />
                        </TableCell>
                        <TableCell>
                          <Switch
                            checked={row.wg_enabled}
                            disabled={
                              wgDriverDown
                              || enableWg.isPending
                              || disableWg.isPending
                              || deleteUser.isPending
                            }
                            onCheckedChange={(c) => handleToggleWg(row, c)}
                            aria-label={t('users.toggleWgAria', { name: row.name })}
                          />
                        </TableCell>
                        <TableCell>
                          <Switch
                            checked={row.proxy_enabled}
                            disabled={
                              proxyDriverDown
                              || enableProxy.isPending
                              || disableProxy.isPending
                              || deleteUser.isPending
                            }
                            onCheckedChange={(c) => handleToggleProxy(row, c)}
                            aria-label={t('users.toggleProxyAria', { name: row.name })}
                          />
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {formatTimestamp(row.created_at)}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="inline-flex items-center gap-1">
                            <Link
                              to="/users/$name"
                              params={{ name: row.name }}
                              aria-label={t('users.openAria', { name: row.name })}
                              className={buttonVariants({ variant: 'ghost', size: 'sm' })}
                            >
                              <KeyRound className="h-3.5 w-3.5" />
                              <span className="ml-1.5">{t('users.detail')}</span>
                            </Link>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={deleteUser.isPending}
                              onClick={() => handleDelete(row)}
                              aria-label={t('users.deleteAria', { name: row.name })}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-destructive" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
          </TableBody>
        </Table>
      </div>

      {(ssDriverDown || wgDriverDown || proxyDriverDown) && (
        <DriverWarning
          ssDown={ssDriverDown}
          wgDown={wgDriverDown}
          proxyDown={proxyDriverDown}
        />
      )}
      {(ssPaused || wgPaused || proxyPaused) && (
        <DriverPausedHint
          ssPaused={ssPaused}
          wgPaused={wgPaused}
          proxyPaused={proxyPaused}
        />
      )}

      {filtered.length > PAGE_SIZE
        ? (
            <div className="flex items-center justify-end gap-2 text-xs text-muted-foreground">
              <span>{t('common.pageXofY', { page: safePage + 1, total: totalPages })}</span>
              <Button
                variant="outline"
                size="icon"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={safePage === 0}
                aria-label={t('common.previousPage')}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="icon"
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={safePage >= totalPages - 1}
                aria-label={t('common.nextPage')}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )
        : null}

      <NewUserDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        ssAvailable={!ssDriverDown}
        wgAvailable={!wgDriverDown}
        onSsCreated={showSsCreated}
        onWgCreated={showWgCreated}
      />

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

function DriverWarning({
  ssDown,
  wgDown,
  proxyDown,
}: {
  ssDown: boolean;
  wgDown: boolean;
  proxyDown: boolean;
}) {
  const { t } = useTranslation();
  const parts: string[] = [];
  if (ssDown)
    parts.push(t('common.protocolStrip.shadowsocks'));
  if (wgDown)
    parts.push(t('common.protocolStrip.wireguard'));
  if (proxyDown)
    parts.push(t('common.protocolStrip.proxy'));
  const protos = parts.join(t('users.driverJoiner'));
  const text
    = parts.length > 1
      ? t('users.driverWarningMany', { protos })
      : t('users.driverWarningOne', { proto: protos });
  return (
    <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
      {text}
    </div>
  );
}

function DriverPausedHint({
  ssPaused,
  wgPaused,
  proxyPaused,
}: {
  ssPaused: boolean;
  wgPaused: boolean;
  proxyPaused: boolean;
}) {
  const { t } = useTranslation();
  const parts: string[] = [];
  if (ssPaused)
    parts.push(t('common.protocolStrip.shadowsocks'));
  if (wgPaused)
    parts.push(t('common.protocolStrip.wireguard'));
  if (proxyPaused)
    parts.push(t('common.protocolStrip.proxy'));
  const protos = parts.join(t('users.driverJoiner'));
  return (
    <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
      {t('users.driverPaused', { protos })}
    </div>
  );
}

interface NewUserDialogProps {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  ssAvailable: boolean;
  wgAvailable: boolean;
  onSsCreated: (material: UserSsEnabled) => void;
  onWgCreated: (material: UserWgEnabled) => void;
}

function NewUserDialog({
  open,
  onOpenChange,
  ssAvailable,
  wgAvailable,
  onSsCreated,
  onWgCreated,
}: NewUserDialogProps) {
  const toaster = useToaster();
  const { t } = useTranslation();
  const createUser = useCreateUserMutation();
  const enableSs = useEnableUserSsMutation();
  const enableWg = useEnableUserWgMutation();
  const [name, setName] = useState('');
  const [note, setNote] = useState('');
  const [enableSsOnCreate, setEnableSsOnCreate] = useState(ssAvailable);
  const [enableWgOnCreate, setEnableWgOnCreate] = useState(wgAvailable);

  useEffect(() => {
    if (!open)
      return;
    /* eslint-disable react/set-state-in-effect */
    setEnableSsOnCreate(ssAvailable);
    setEnableWgOnCreate(wgAvailable);
    /* eslint-enable react/set-state-in-effect */
  }, [open, ssAvailable, wgAvailable]);

  const reset = () => {
    setName('');
    setNote('');
    setEnableSsOnCreate(ssAvailable);
    setEnableWgOnCreate(wgAvailable);
  };

  const onSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed)
      return;
    try {
      const user = await createUser.mutateAsync({
        name: trimmed,
        note: note.trim() ? note.trim() : null,
      });
      const failures: string[] = [];
      if (enableSsOnCreate) {
        try {
          onSsCreated(await enableSs.mutateAsync(user.id));
        }
        catch (err) {
          failures.push(`${t('common.protocolStrip.shadowsocks')}: ${formatApiError(err)}`);
        }
      }
      if (enableWgOnCreate) {
        try {
          onWgCreated(await enableWg.mutateAsync({ id: user.id }));
        }
        catch (err) {
          failures.push(`${t('common.protocolStrip.wireguard')}: ${formatApiError(err)}`);
        }
      }
      if (failures.length > 0) {
        toaster.error(t('users.toasts.protocolEnableFailed'), failures.join('\n'));
      }
      else {
        toaster.success(t('users.toasts.created'));
      }
      reset();
      onOpenChange(false);
    }
    catch (err) {
      toaster.error(t('users.toasts.createFailed'), formatApiError(err));
    }
  };

  const pending = createUser.isPending || enableSs.isPending || enableWg.isPending;

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v)
          reset();
        onOpenChange(v);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('users.dialog.title')}</DialogTitle>
          <DialogDescription>{t('users.dialog.description')}</DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="grid gap-3">
          <div className="grid gap-2">
            <Label htmlFor="name">{t('users.dialog.nameLabel')}</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              maxLength={32}
              pattern="[A-Za-z0-9_\-]{1,32}"
              placeholder={t('users.dialog.namePlaceholder')}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="note">{t('users.dialog.noteLabel')}</Label>
            <Input
              id="note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={t('users.dialog.notePlaceholder')}
            />
          </div>
          <div className="grid gap-2 rounded-md border border-border p-3">
            <div className="flex items-center justify-between">
              <Label htmlFor="enable-ss">{t('users.dialog.shadowsocks')}</Label>
              <Switch
                id="enable-ss"
                checked={enableSsOnCreate}
                disabled={!ssAvailable}
                onCheckedChange={setEnableSsOnCreate}
                aria-label={t('users.dialog.enableSsAria')}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="enable-wg">{t('users.dialog.wireguard')}</Label>
              <Switch
                id="enable-wg"
                checked={enableWgOnCreate}
                disabled={!wgAvailable}
                onCheckedChange={setEnableWgOnCreate}
                aria-label={t('users.dialog.enableWgAria')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
              disabled={pending}
            >
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? t('users.dialog.submitting') : t('users.dialog.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function slug(s: string): string {
  return s.replace(/[^\w-]+/g, '_').slice(0, 64);
}

function formatApiError(err: unknown): string {
  return err instanceof ApiError ? err.message : String(err);
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

export default UsersPage;
