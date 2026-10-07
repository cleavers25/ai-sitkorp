"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bell,
  CalendarClock,
  ClipboardCheck,
  Globe,
  HardDrive,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Send,
  Server,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserCog,
  Users,
  Wrench,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import type { Permission } from "@/lib/types";
import { cn } from "@/lib/utils";

type NavItem = { href: string; label: string; icon: typeof Server; perm: Permission; badge?: "actions" | "notifications" };
const NAV: { section: string | null; items: NavItem[] }[] = [
  { section: null, items: [
    { href: "/", label: "Dashboard", icon: LayoutDashboard, perm: "dashboard:view" },
    { href: "/assistant", label: "AI Assistant", icon: Sparkles, perm: "asset:view" },
    { href: "/notifications", label: "Notifikasi", icon: Bell, perm: "asset:view", badge: "notifications" },
  ] },
  { section: "Operasional", items: [
    { href: "/servers", label: "Server", icon: Server, perm: "asset:view" },
    { href: "/websites", label: "Website", icon: Globe, perm: "asset:view" },
    { href: "/assessments", label: "Assessment", icon: ClipboardCheck, perm: "asset:view" },
    { href: "/schedules", label: "Jadwal", icon: CalendarClock, perm: "asset:view" },
    { href: "/backups", label: "Backup", icon: HardDrive, perm: "asset:view" },
  ] },
  { section: "Keamanan", items: [
    { href: "/findings", label: "Findings", icon: ShieldAlert, perm: "asset:view" },
    { href: "/actions", label: "Tindakan", icon: Wrench, perm: "asset:view", badge: "actions" },
    { href: "/audit", label: "Audit Log", icon: ScrollText, perm: "audit:view" },
  ] },
  { section: "Pengaturan", items: [
    { href: "/credentials", label: "Credential", icon: KeyRound, perm: "credential:view" },
    { href: "/users", label: "User", icon: Users, perm: "user:manage" },
    { href: "/settings/ai", label: "AI & Memory", icon: Settings2, perm: "ai:config" },
    { href: "/settings/notifications", label: "Kanal notifikasi", icon: Send, perm: "notify:manage" },
    { href: "/settings/wazuh", label: "Integrasi Wazuh", icon: Radar, perm: "integration:manage" },
  ] },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const qc = useQueryClient();
  const { me, can, isLoading } = useMe();
  const [open, setOpen] = useState(false);

  const logout = useMutation({
    mutationFn: () => api("/auth/logout", { method: "POST" }),
    onSettled: () => {
      qc.clear();
      router.replace("/login");
    },
  });

  const pending = useQuery({
    queryKey: ["actions-pending"],
    queryFn: () => api<{ pending: number }>("/actions/pending-count"),
    refetchInterval: 30_000,
    enabled: can("asset:view"),
  });

  const unread = useQuery({
    queryKey: ["notifications-unread"],
    queryFn: () => api<{ unread: number }>("/notifications/unread-count"),
    refetchInterval: 30_000,
    enabled: can("asset:view"),
  });
  const badges = { actions: pending.data?.pending ?? 0, notifications: unread.data?.unread ?? 0 };

  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  const nav = (
    <nav className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto">
      {NAV.map(({ section, items }) => {
        const visible = items.filter((n) => can(n.perm));
        if (!visible.length) return null;
        return (
          <div key={section ?? "main"} className="mb-1.5">
            {section && <p className="px-2.5 pt-2 pb-1 text-[11px] font-medium tracking-wide text-muted-foreground/80 uppercase">{section}</p>}
            {visible.map(({ href, label, icon: Icon, badge }) => (
              <Link
                key={href}
                href={href}
                onClick={() => setOpen(false)}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                  isActive(href)
                    ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
                )}
              >
                <Icon className="size-4" />
                {label}
                {badge && badges[badge] > 0 && (
                  <span className={cn("ml-auto rounded-full px-1.5 text-[11px] font-semibold text-white",
                    badge === "actions" ? "bg-amber-500" : "bg-red-500")}>
                    {badges[badge] > 99 ? "99+" : badges[badge]}
                  </span>
                )}
              </Link>
            ))}
          </div>
        );
      })}
    </nav>
  );

  return (
    <div className="min-h-dvh md:grid md:grid-cols-[15rem_1fr]">
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r bg-sidebar p-3 transition-transform md:sticky md:top-0 md:h-dvh md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="mb-5 flex items-center gap-2 px-2 pt-1">
          <ShieldCheck className="size-5 text-primary" />
          <div className="leading-tight">
            <p className="text-sm font-semibold">AI Infra Assistant</p>
            <p className="text-[11px] text-muted-foreground">Security &amp; Operations</p>
          </div>
        </div>
        {!isLoading && nav}
        <div className="mt-auto border-t pt-3">
          {me && (
            <Link href="/account" onClick={() => setOpen(false)} className="block rounded-md px-2 py-1.5 hover:bg-sidebar-accent/60">
              <p className="truncate text-sm font-medium">{me.full_name}</p>
              <p className="flex items-center gap-1 truncate text-xs text-muted-foreground">
                <UserCog className="size-3" />
                {me.role} · {me.email}
              </p>
            </Link>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="mt-1 w-full justify-start text-muted-foreground"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
          >
            <LogOut /> Keluar
          </Button>
        </div>
      </aside>

      {open && <div className="fixed inset-0 z-30 bg-black/30 md:hidden" onClick={() => setOpen(false)} />}

      <div className="min-w-0">
        <header className="sticky top-0 z-20 flex h-12 items-center border-b bg-background/90 px-4 backdrop-blur md:hidden">
          <Button variant="ghost" size="icon" aria-label="Buka menu" onClick={() => setOpen(true)}>
            <Menu />
          </Button>
          <span className="ml-2 text-sm font-semibold">AI Infra Assistant</span>
        </header>
        <main className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">{children}</main>
      </div>
    </div>
  );
}
