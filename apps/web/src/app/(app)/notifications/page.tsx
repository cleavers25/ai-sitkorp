"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCheck, Settings2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { EmptyState, PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/status";
import { Button, buttonVariants } from "@/components/ui/button";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { NotificationEvent, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE = 30;

export default function NotificationsPage() {
  const qc = useQueryClient();
  const { can } = useMe();
  const [limit, setLimit] = useState(PAGE);
  const types = useQuery({
    queryKey: ["notification-event-types"],
    queryFn: () => api<Record<string, string>>("/notifications/event-types"),
  });
  const events = useQuery({
    queryKey: ["notification-events", limit],
    queryFn: () => api<Page<NotificationEvent>>(`/notifications/events?limit=${limit}`),
    refetchInterval: 30_000,
  });
  const unread = useQuery({
    queryKey: ["notifications-unread"],
    queryFn: () => api<{ unread: number }>("/notifications/unread-count"),
  });

  // Unread count captured on first load, so the "new" highlight survives marking them as seen.
  const [newCount, setNewCount] = useState<number | null>(null);
  const seen = useMutation({
    mutationFn: () => api("/notifications/seen", { method: "POST" }),
    onSuccess: () => qc.setQueryData(["notifications-unread"], { unread: 0 }),
  });
  const marked = useRef(false);
  useEffect(() => {
    if (unread.data && newCount === null) setNewCount(unread.data.unread);
    if (unread.data?.unread && !marked.current) {
      marked.current = true;
      seen.mutate();
    }
  }, [unread.data, newCount, seen]);

  const items = events.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Notifikasi"
        description="Kejadian penting dari assessment, backup, tindakan, laporan AI, dan Wazuh. Kejadian yang sama juga dikirim ke kanal email/webhook/Telegram yang aktif."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => seen.mutate()} disabled={seen.isPending}>
              <CheckCheck /> Tandai sudah dibaca
            </Button>
            {can("notify:manage") && (
              <Link href="/settings/notifications" className={buttonVariants({ variant: "outline", size: "sm" })}>
                <Settings2 /> Kanal notifikasi
              </Link>
            )}
          </>
        }
      />
      {events.isSuccess && !items.length ? (
        <EmptyState title="Belum ada notifikasi">
          Notifikasi muncul saat status asset memburuk, ada temuan baru, malware, backup gagal, tindakan menunggu persetujuan, dll.
        </EmptyState>
      ) : (
        <div className="divide-y rounded-xl border">
          {items.map((e, i) => {
            const isNew = newCount !== null && i < newCount;
            const body = (
              <div className={cn("flex gap-3 p-3", isNew && "bg-sky-50/60 dark:bg-sky-950/30")}>
                <div className="w-20 shrink-0 pt-0.5"><SeverityBadge severity={e.severity} /></div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <p className="font-medium">{e.title}</p>
                    <span className="text-xs text-muted-foreground">{types.data?.[e.type] ?? e.type}</span>
                    {isNew && <span className="rounded bg-sky-600 px-1.5 text-[10px] font-semibold text-white uppercase">baru</span>}
                  </div>
                  {e.body && <p className="mt-0.5 line-clamp-3 text-sm whitespace-pre-line text-muted-foreground">{e.body}</p>}
                </div>
                <span className="shrink-0 text-xs text-muted-foreground">{formatDateTime(e.created_at)}</span>
              </div>
            );
            return e.link ? (
              <Link key={e.id} href={e.link} className="block hover:bg-muted/40">{body}</Link>
            ) : (
              <div key={e.id}>{body}</div>
            );
          })}
        </div>
      )}
      {events.data && events.data.total > items.length && (
        <div className="mt-4 text-center">
          <Button variant="outline" size="sm" onClick={() => setLimit(limit + PAGE)}>Muat lebih banyak</Button>
        </div>
      )}
    </>
  );
}
