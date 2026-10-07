"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Mail, Pencil, Plus, Send, Trash2, Webhook, XCircle } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { Field, FormError, NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { ChannelKind, NotificationChannel, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

const KIND: Record<ChannelKind, { label: string; icon: typeof Mail; secret: string; secretHint: string }> = {
  EMAIL: { label: "Email (SMTP)", icon: Mail, secret: "Password SMTP", secretHint: "Kosongkan jika server SMTP tidak memakai login." },
  WEBHOOK: {
    label: "Webhook",
    icon: Webhook,
    secret: "Signing secret (opsional)",
    secretHint: "Jika diisi, setiap request membawa header X-AIInfra-Signature: sha256=<HMAC body>.",
  },
  TELEGRAM: { label: "Telegram", icon: Send, secret: "Bot token", secretHint: "Token dari @BotFather, contoh 123456:ABC-..." },
};

interface Delivery {
  id: string;
  event_title: string | null;
  channel_name: string | null;
  state: "PENDING" | "SENT" | "FAILED";
  attempts: number;
  last_error: string | null;
  sent_at: string | null;
  created_at: string;
}

type Form = {
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  events: string[];
  secret: string;
  clearSecret: boolean;
  host: string;
  port: string;
  security: string;
  username: string;
  from_address: string;
  to: string;
  verify_tls: boolean;
  url: string;
  format: string;
  chat_id: string;
};

function toForm(ch: NotificationChannel | undefined, allEvents: string[]): Form {
  const c = (ch?.config ?? {}) as Record<string, unknown>;
  const str = (k: string, d = "") => (c[k] == null ? d : String(c[k]));
  return {
    name: ch?.name ?? "",
    kind: ch?.kind ?? "EMAIL",
    enabled: ch?.enabled ?? true,
    events: ch?.events ?? allEvents.filter((e) => e !== "daily_report"),
    secret: "",
    clearSecret: false,
    host: str("host"),
    port: str("port", "587"),
    security: str("security", "starttls"),
    username: str("username"),
    from_address: str("from_address"),
    to: Array.isArray(c.to) ? (c.to as string[]).join(", ") : "",
    verify_tls: c.verify_tls !== false,
    url: str("url"),
    format: str("format", "json"),
    chat_id: str("chat_id"),
  };
}

function configOf(f: Form): Record<string, unknown> {
  if (f.kind === "EMAIL")
    return {
      host: f.host.trim(),
      port: Number(f.port) || 587,
      security: f.security,
      username: f.username.trim() || null,
      from_address: f.from_address.trim(),
      to: f.to.split(/[,;\s]+/).filter(Boolean),
      verify_tls: f.verify_tls,
    };
  if (f.kind === "WEBHOOK") return { url: f.url.trim(), format: f.format, verify_tls: f.verify_tls };
  return { chat_id: f.chat_id.trim() };
}

function ChannelDialog({
  channel,
  eventTypes,
  onClose,
}: {
  channel?: NotificationChannel;
  eventTypes: Record<string, string>;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [f, setF] = useState<Form>(() => toForm(channel, Object.keys(eventTypes)));
  const set = (k: keyof Form) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { name: f.name.trim(), enabled: f.enabled, events: f.events, config: configOf(f) };
      if (f.secret) body.secret = f.secret;
      else if (f.clearSecret) body.secret = "";
      if (channel) return api<NotificationChannel>(`/notifications/channels/${channel.id}`, { method: "PATCH", json: body });
      return api<NotificationChannel>("/notifications/channels", { method: "POST", json: { ...body, kind: f.kind } });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      toast.success("Kanal disimpan");
      onClose();
    },
  });
  const k = KIND[f.kind];

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{channel ? `Ubah kanal "${channel.name}"` : "Tambah kanal notifikasi"}</DialogTitle>
          <DialogDescription>
            Rahasia (password SMTP, signing secret, bot token) disimpan terenkripsi dan tidak pernah ditampilkan lagi.
          </DialogDescription>
        </DialogHeader>
        <form id="ch-form" className="grid gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Nama" htmlFor="ch-name">
            <Input id="ch-name" required value={f.name} onChange={set("name")} placeholder="mis. Email tim SOC" />
          </Field>
          <Field label="Jenis" htmlFor="ch-kind">
            <NativeSelect id="ch-kind" value={f.kind} disabled={!!channel} onChange={(e) => setF({ ...f, kind: e.target.value as ChannelKind })}>
              {Object.entries(KIND).map(([key, v]) => <option key={key} value={key}>{v.label}</option>)}
            </NativeSelect>
          </Field>

          {f.kind === "EMAIL" && (
            <>
              <Field label="SMTP host" htmlFor="ch-host">
                <Input id="ch-host" value={f.host} onChange={set("host")} placeholder="smtp.kantor.co.id" />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Port" htmlFor="ch-port">
                  <Input id="ch-port" type="number" min={1} max={65535} value={f.port} onChange={set("port")} />
                </Field>
                <Field label="Keamanan" htmlFor="ch-sec">
                  <NativeSelect
                    id="ch-sec"
                    value={f.security}
                    onChange={(e) => {
                      const security = e.target.value;
                      const port = { starttls: "587", ssl: "465", none: "25" }[security] ?? f.port;
                      setF({ ...f, security, port });
                    }}
                  >
                    <option value="starttls">STARTTLS</option>
                    <option value="ssl">SSL/TLS</option>
                    <option value="none">Tanpa enkripsi</option>
                  </NativeSelect>
                </Field>
              </div>
              <Field label="Username SMTP" htmlFor="ch-user" hint="Kosongkan jika relay tanpa login.">
                <Input id="ch-user" value={f.username} onChange={set("username")} autoComplete="off" />
              </Field>
              <Field label="Alamat pengirim" htmlFor="ch-from">
                <Input id="ch-from" value={f.from_address} onChange={set("from_address")} placeholder="AI Infra <noreply@kantor.co.id>" />
              </Field>
              <Field label="Penerima" htmlFor="ch-to" hint="Pisahkan dengan koma." className="sm:col-span-2">
                <Input id="ch-to" value={f.to} onChange={set("to")} placeholder="soc@kantor.co.id, it@kantor.co.id" />
              </Field>
            </>
          )}

          {f.kind === "WEBHOOK" && (
            <>
              <Field label="URL" htmlFor="ch-url" className="sm:col-span-2">
                <Input id="ch-url" value={f.url} onChange={set("url")} placeholder="https://hooks.example.com/..." />
              </Field>
              <Field
                label="Format"
                htmlFor="ch-fmt"
                hint={f.format === "slack" ? "Body {text: ...}, cocok untuk Slack, Mattermost, Google Chat, Rocket.Chat." : "JSON lengkap: event, severity, title, body, asset_id, url, data."}
              >
                <NativeSelect id="ch-fmt" value={f.format} onChange={set("format")}>
                  <option value="json">JSON (generik)</option>
                  <option value="slack">Slack-compatible</option>
                </NativeSelect>
              </Field>
            </>
          )}

          {f.kind === "TELEGRAM" && (
            <Field label="Chat ID" htmlFor="ch-chat" hint="ID grup/user, mis. -1001234567890">
              <Input id="ch-chat" value={f.chat_id} onChange={set("chat_id")} />
            </Field>
          )}

          <Field
            label={k.secret}
            htmlFor="ch-secret"
            hint={channel?.has_secret ? "Tersimpan. Isi hanya jika ingin mengganti." : k.secretHint}
            className={f.kind === "TELEGRAM" ? "" : "sm:col-span-2"}
          >
            <Input
              id="ch-secret"
              type="password"
              autoComplete="new-password"
              value={f.secret}
              onChange={set("secret")}
              placeholder={channel?.has_secret ? "••••••••" : ""}
            />
          </Field>
          {channel?.has_secret && f.kind !== "TELEGRAM" && (
            <label className="-mt-2 flex items-center gap-2 text-sm sm:col-span-2">
              <input type="checkbox" checked={f.clearSecret} onChange={(e) => setF({ ...f, clearSecret: e.target.checked })} />
              Hapus {k.secret.toLowerCase()} yang tersimpan
            </label>
          )}
          {f.kind !== "TELEGRAM" && (
            <label className="flex items-center gap-2 text-sm sm:col-span-2">
              <input type="checkbox" checked={f.verify_tls} onChange={(e) => setF({ ...f, verify_tls: e.target.checked })} />
              Verifikasi sertifikat TLS (matikan hanya untuk server internal dengan sertifikat self-signed)
            </label>
          )}

          <div className="sm:col-span-2">
            <p className="mb-1.5 text-sm font-medium">Kirim untuk kejadian</p>
            <div className="grid gap-1 rounded-md border p-2.5 text-sm sm:grid-cols-2">
              {Object.entries(eventTypes).map(([key, label]) => (
                <label key={key} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={f.events.includes(key)}
                    onChange={() => setF({ ...f, events: f.events.includes(key) ? f.events.filter((x) => x !== key) : [...f.events, key] })}
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />
            Aktif
          </label>
          <div className="sm:col-span-2"><FormError message={save.error?.message ?? null} /></div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="ch-form" disabled={save.isPending}>Simpan</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function summary(ch: NotificationChannel): string {
  const c = ch.config as Record<string, unknown>;
  if (ch.kind === "EMAIL") {
    const to = Array.isArray(c.to) ? (c.to as string[]) : [];
    return c.host ? `${c.host}:${c.port ?? 587} → ${to.join(", ") || "(belum ada penerima)"}` : "SMTP belum diisi";
  }
  if (ch.kind === "WEBHOOK") return c.url ? `${c.format === "slack" ? "Slack · " : ""}${c.url}` : "URL belum diisi";
  return c.chat_id ? `chat ${c.chat_id}` : "Chat ID belum diisi";
}

const DELIVERY_CLS = {
  SENT: "text-emerald-700 dark:text-emerald-400",
  PENDING: "text-sky-700 dark:text-sky-400",
  FAILED: "text-red-700 dark:text-red-400",
};

export default function NotificationChannelsPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<NotificationChannel | "new" | null>(null);
  const [deleting, setDeleting] = useState<NotificationChannel | null>(null);
  const types = useQuery({
    queryKey: ["notification-event-types"],
    queryFn: () => api<Record<string, string>>("/notifications/event-types"),
  });
  const channels = useQuery({
    queryKey: ["notification-channels"],
    queryFn: () => api<NotificationChannel[]>("/notifications/channels"),
  });
  const deliveries = useQuery({
    queryKey: ["notification-deliveries"],
    queryFn: () => api<Page<Delivery>>("/notifications/deliveries?limit=30"),
    refetchInterval: (q) => (q.state.data?.items.some((d) => d.state === "PENDING") ? 5000 : 30_000),
  });
  const test = useMutation({
    mutationFn: (ch: NotificationChannel) => api<{ ok: boolean; message: string }>(`/notifications/channels/${ch.id}/test`, { method: "POST" }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      if (r.ok) toast.success(r.message || "Pesan uji terkirim");
      else toast.error(r.message);
    },
  });
  const toggle = useMutation({
    mutationFn: (ch: NotificationChannel) =>
      api(`/notifications/channels/${ch.id}`, { method: "PATCH", json: { enabled: !ch.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notification-channels"] }),
  });
  const remove = useMutation({
    mutationFn: (ch: NotificationChannel) => api(`/notifications/channels/${ch.id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      toast.success("Kanal dihapus");
      setDeleting(null);
    },
  });

  const list = channels.data ?? [];
  return (
    <>
      <PageHeader
        title="Kanal notifikasi"
        description="Ke mana kejadian penting dikirim: email (SMTP), webhook (JSON/Slack-compatible), atau Telegram. Semua notifikasi juga tampil di menu Notifikasi."
        actions={<Button size="sm" onClick={() => setEditing("new")} disabled={!types.data}><Plus /> Tambah kanal</Button>}
      />

      {channels.isSuccess && !list.length ? (
        <EmptyState title="Belum ada kanal">
          Tambahkan kanal Email untuk SMTP kantor, atau Webhook untuk Slack/Teams/sistem tiket. Kanal bisa dibuat sekarang lalu dilengkapi nanti.
        </EmptyState>
      ) : (
        <div className="grid gap-3">
          {list.map((ch) => {
            const Icon = KIND[ch.kind].icon;
            return (
              <Card key={ch.id} className={cn(!ch.enabled && "opacity-70")}>
                <CardContent className="flex flex-wrap items-start gap-4">
                  <Icon className="mt-0.5 size-5 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-medium">{ch.name}</p>
                      <span className="text-xs text-muted-foreground">{KIND[ch.kind].label}</span>
                      {!ch.enabled && <span className="rounded bg-muted px-1.5 text-[11px]">nonaktif</span>}
                    </div>
                    <p className="truncate text-sm text-muted-foreground">{summary(ch)}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {ch.events.length ? ch.events.map((e) => types.data?.[e] ?? e).join(" · ") : "Tidak ada kejadian dipilih"}
                    </p>
                    {ch.last_test_at && (
                      <p className={cn("mt-1 flex items-center gap-1 text-xs", ch.last_test_ok ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400")}>
                        {ch.last_test_ok ? <CheckCircle2 className="size-3.5" /> : <XCircle className="size-3.5" />}
                        Tes {formatDateTime(ch.last_test_at)}{ch.last_test_ok ? ": berhasil" : `: ${ch.last_test_error}`}
                      </p>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <Button variant="outline" size="sm" onClick={() => test.mutate(ch)} disabled={test.isPending}>
                      <Send /> Kirim uji
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => toggle.mutate(ch)}>{ch.enabled ? "Nonaktifkan" : "Aktifkan"}</Button>
                    <Button variant="ghost" size="icon-sm" aria-label="Ubah" onClick={() => setEditing(ch)}><Pencil /></Button>
                    <Button variant="ghost" size="icon-sm" aria-label="Hapus" onClick={() => setDeleting(ch)}><Trash2 /></Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <Card className="mt-8">
        <CardHeader><CardTitle className="text-base">Riwayat pengiriman</CardTitle></CardHeader>
        <CardContent>
          {!deliveries.data?.items.length ? (
            <p className="text-sm text-muted-foreground">Belum ada pengiriman. Gagal kirim dicoba ulang otomatis hingga 3 kali (1 menit, lalu 5 menit).</p>
          ) : (
            <div className="divide-y text-sm">
              {deliveries.data.items.map((d) => (
                <div key={d.id} className="flex flex-wrap gap-x-3 gap-y-0.5 py-2">
                  <span className="w-36 text-xs text-muted-foreground">{formatDateTime(d.created_at)}</span>
                  <span className={cn("w-16 text-xs font-semibold", DELIVERY_CLS[d.state])}>{d.state}</span>
                  <span className="w-40 truncate text-xs">{d.channel_name ?? "(kanal dihapus)"}</span>
                  <span className="min-w-0 flex-1 truncate">{d.event_title}</span>
                  {d.attempts > 1 && <span className="text-xs text-muted-foreground">{d.attempts}× percobaan</span>}
                  {d.last_error && d.state !== "SENT" && <p className="w-full pl-39 text-xs text-red-700 dark:text-red-400">{d.last_error}</p>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {editing && types.data && (
        <ChannelDialog channel={editing === "new" ? undefined : editing} eventTypes={types.data} onClose={() => setEditing(null)} />
      )}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Hapus kanal?"
        description={`Kanal "${deleting?.name}" beserta rahasia dan riwayat pengirimannya akan dihapus. Jejak di audit log tetap ada.`}
        confirmLabel="Hapus"
        onConfirm={() => deleting && remove.mutate(deleting)}
        pending={remove.isPending}
      />
    </>
  );
}
