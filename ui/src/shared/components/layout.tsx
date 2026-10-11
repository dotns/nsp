import type { ReactNode } from 'react';
import { Link, Outlet, useNavigate } from '@tanstack/react-router';
import {
  FileClock,
  Github,
  LogOut,
  Server,
  Settings,
  ShieldAlert,
  Users,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useStatusQuery } from '@/features/services/api';
import { LanguageSwitcher } from '@/shared/components/language-switcher';
import { Logo } from '@/shared/components/logo';
import { ModeToggle } from '@/shared/components/mode-toggle';
import { Button } from '@/shared/components/ui/button';
import { cn } from '@/shared/lib/utils';
import { authStore } from '@/shared/stores/auth';

export function Layout() {
  const navigate = useNavigate();
  const { t } = useTranslation();

  const handleLogout = () => {
    authStore.clear();
    void navigate({ to: '/login', replace: true });
  };

  return (
    <div className="flex min-h-full flex-col bg-background text-foreground">
      <header className="border-b border-border bg-card/40">
        <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4">
          <Link to="/users" className="flex items-center gap-2 transition-opacity hover:opacity-80">
            <Logo width={22} height={22} />
            <span className="text-base font-semibold tracking-tight">{t('common.appName')}</span>
          </Link>
          <nav className="flex items-center gap-1">
            <NavTab
              to="/users"
              icon={<Users className="h-4 w-4" />}
              label={t('common.nav.users')}
            />
            <NavTab
              to="/services"
              icon={<Server className="h-4 w-4" />}
              label={t('common.nav.services')}
            />
            <NavTab
              to="/iptables"
              icon={<ShieldAlert className="h-4 w-4" />}
              label={t('common.nav.iptables')}
            />
            <NavTab
              to="/audit"
              icon={<FileClock className="h-4 w-4" />}
              label={t('common.nav.audit')}
            />
            <NavTab
              to="/settings"
              icon={<Settings className="h-4 w-4" />}
              label={t('common.nav.settings')}
            />
          </nav>
          <div className="flex items-center gap-1">
            <ModeToggle />
            <LanguageSwitcher />
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              aria-label={t('common.signOut')}
            >
              <LogOut className="h-4 w-4" />
              <span className="ml-2">{t('common.signOut')}</span>
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
        <Outlet />
      </main>

      <footer className="border-t border-border py-3">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 text-xs text-muted-foreground">
          <a
            href="https://github.com/dotns/nsp"
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1.5 transition-colors hover:text-foreground"
          >
            <Github className="h-3.5 w-3.5" />
            dotns/nsp
          </a>
          <ProtocolStatus />
        </div>
      </footer>
    </div>
  );
}

interface NavTabProps {
  to: '/users' | '/services' | '/iptables' | '/audit' | '/settings';
  icon: ReactNode;
  label: string;
}

function NavTab({ to, icon, label }: NavTabProps) {
  return (
    <Link
      to={to}
      className="inline-flex h-9 items-center gap-2 rounded-md px-3 text-sm transition-colors"
      activeProps={{ className: 'bg-secondary text-secondary-foreground' }}
      inactiveProps={{ className: 'text-muted-foreground hover:bg-secondary/50 hover:text-foreground' }}
    >
      {icon}
      {label}
    </Link>
  );
}

function ProtocolStatus() {
  const status = useStatusQuery();
  const { t } = useTranslation();

  if (status.isError) {
    return <span className="text-destructive">{t('common.statusUnavailable')}</span>;
  }

  const ss = status.data?.ss_enabled ?? false;
  const wg = status.data?.wg_enabled ?? false;

  return (
    <div className="flex items-center gap-3">
      <ProtocolDot label={t('common.protocolStrip.shadowsocks')} on={ss} />
      <ProtocolDot label={t('common.protocolStrip.wireguard')} on={wg} />
      {status.data
        ? (
            <span className="font-mono">
              v
              {status.data.version}
            </span>
          )
        : null}
    </div>
  );
}

function ProtocolDot({ label, on }: { label: string; on: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1.5"
      title={label}
      aria-label={label}
    >
      <span
        className={cn(
          'inline-block h-2 w-2 rounded-full',
          on ? 'bg-emerald-400' : 'bg-muted-foreground/40',
        )}
      />
      <span>{label}</span>
    </span>
  );
}
