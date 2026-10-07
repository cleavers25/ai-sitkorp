"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Loader2, Play, Plus, SendHorizontal, Wrench } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AIConversation, AIConversationDetail, AIMessage, AIProposal, Page, Permission } from "@/lib/types";
import { cn } from "@/lib/utils";

const TOOL_LABEL: Record<string, string> = {
  list_assets: "daftar asset",
  get_asset: "detail asset",
  list_findings: "daftar temuan",
  get_finding: "detail temuan",
  get_assessment: "hasil assessment",
  compare_assessments: "perbandingan assessment",
  dashboard_summary: "ringkasan dashboard",
  propose_action: "usulan aksi",
};

const GLOBAL_SUGGESTIONS = [
  "Server/website mana saja yang statusnya RED, dan kenapa?",
  "Tampilkan semua temuan CRITICAL dan HIGH yang masih terbuka.",
  "Website mana yang sertifikat SSL-nya bermasalah?",
  "Asset mana yang belum pernah di-assess?",
];
const ASSET_SUGGESTIONS = [
  "Kenapa statusnya seperti ini?",
  "Apa yang berubah sejak assessment sebelumnya?",
  "Apakah ada indikasi malware? Jelaskan evidence-nya.",
  "Apa prioritas perbaikan yang kamu sarankan?",
];

const REMEDIATION: Record<string, { kind: string; label: string; params: (p: AIProposal) => Record<string, string> }> = {
  quarantine_file: { kind: "QUARANTINE_FILE", label: "karantina file", params: (p) => ({ path: p.path ?? "" }) },
  restrict_file: { kind: "RESTRICT_FILE", label: "batasi akses file", params: (p) => ({ path: p.path ?? "" }) },
  restart_service: { kind: "RESTART_SERVICE", label: "restart service", params: (p) => ({ service: p.service ?? "" }) },
};

function ProposalCard({ p }: { p: AIProposal }) {
  const qc = useQueryClient();
  const { can } = useMe();
  const [done, setDone] = useState(false);
  const remediation = REMEDIATION[p.action];

  const act = useMutation({
    mutationFn: () => {
      if (p.action === "run_assessment") return api(`/assets/${p.asset_id}/assess`, { method: "POST" });
      if (p.action === "save_memory")
        return api("/memories", { method: "POST", json: { asset_id: p.asset_id ?? null, kind: p.kind ?? "OPERATIONAL", content: p.content, source: "AI" } });
      return api("/actions", { method: "POST", json: { asset_id: p.asset_id, kind: remediation.kind, params: remediation.params(p), reason: `[Usulan AI] ${p.reason}` } });
    },
    onSuccess: () => {
      setDone(true);
      if (p.action === "run_assessment") toast.success(`Assessment ${p.asset_name} dijalankan`);
      else if (p.action === "save_memory") toast.success("Disimpan ke memory");
      else toast.success("Permintaan dibuat — menunggu approval di menu Tindakan");
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: ["memories"] });
      qc.invalidateQueries({ queryKey: ["actions"] });
    },
    onError: (e) => toast.error(e.message),
  });

  const href = p.asset_id ? `/${p.asset_type === "SERVER" ? "servers" : "websites"}/${p.asset_id}` : null;
  const target = href ? <Link href={href} className="underline">{p.asset_name}</Link> : null;
  const [title, perm, cta, doneLabel]: [React.ReactNode, Permission, string, string] =
    p.action === "run_assessment"
      ? [<>jalankan assessment untuk {target}</>, "assessment:run", "Jalankan (konfirmasi)", "Sudah dijalankan"]
      : p.action === "save_memory"
        ? [<>simpan catatan ke memory {target ? <>asset {target}</> : "global"}</>, "memory:manage", "Simpan ke memory", "Tersimpan"]
        : [<>{remediation.label} di {target}</>, "action:request", "Ajukan untuk approval", "Menunggu approval"];

  return (
    <div className="mt-2 rounded-lg border border-sky-200 bg-sky-50 p-3 text-sm dark:border-sky-900 dark:bg-sky-950/50">
      <p className="font-medium">Usulan AI: {title}</p>
      {p.content && <p className="mt-1 rounded bg-background/70 px-2 py-1 text-sm">&ldquo;{p.content}&rdquo;</p>}
      {(p.path || p.service) && <p className="mt-1 font-mono text-xs break-all">{p.path ?? p.service}</p>}
      {p.reason && <p className="mt-0.5 text-muted-foreground">{p.reason}</p>}
      <div className="mt-2">
        {can(perm) ? (
          <Button size="sm" onClick={() => act.mutate()} disabled={done || act.isPending}>
            <Play /> {done ? doneLabel : cta}
          </Button>
        ) : (
          <span className="text-xs text-muted-foreground">Role Anda tidak punya izin untuk aksi ini.</span>
        )}
      </div>
    </div>
  );
}

function MessageBubble({ m }: { m: AIMessage }) {
  if (m.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-2xl rounded-br-sm bg-primary px-3.5 py-2 text-sm whitespace-pre-wrap text-primary-foreground">
          {m.content}
        </div>
      </div>
    );
  }
  return (
    <div className="flex gap-2.5">
      <div className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-full bg-muted">
        <Bot className="size-4" />
      </div>
      <div className="min-w-0 max-w-[90%] flex-1">
        {!!m.tool_calls.length && (
          <div className="mb-1.5 flex flex-wrap gap-1">
            {m.tool_calls.map((t, i) => (
              <span
                key={i}
                title={JSON.stringify(t.arguments)}
                className={cn(
                  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground",
                  t.error && "border-amber-300 text-amber-700 dark:text-amber-400",
                )}
              >
                <Wrench className="size-3" /> {TOOL_LABEL[t.name] ?? t.name}
              </span>
            ))}
          </div>
        )}
        {m.error ? (
          <p className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{m.error}</p>
        ) : (
          <div className="prose-chat text-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.content || "_(tidak ada jawaban)_"}</ReactMarkdown>
          </div>
        )}
        {m.proposals.map((p) => <ProposalCard key={p.id} p={p} />)}
        <p className="mt-1 text-[11px] text-muted-foreground">
          {formatDateTime(m.created_at)}{m.model ? ` · ${m.model}` : ""}
        </p>
      </div>
    </div>
  );
}

/** @mention autocomplete for asset names (global chat). */
function useMention(text: string) {
  const match = /(^|\s)@([\w.-]*)$/.exec(text);
  const q = match?.[2] ?? null;
  const assets = useQuery({
    queryKey: ["assets", "mention", q],
    queryFn: () => api<Page<Asset>>(`/assets?limit=8${q ? `&q=${encodeURIComponent(q)}` : ""}`),
    enabled: q !== null,
  });
  return { active: q !== null, options: assets.data?.items ?? [] };
}

type Asset = { id: string; name: string; asset_type: string };

export function ChatPanel({
  assetId,
  conversationId,
  onConversationCreated,
  className,
}: {
  assetId?: string;
  conversationId?: string | null;
  onConversationCreated?: (id: string) => void;
  className?: string;
}) {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [assetConvId, setAssetConvId] = useState<string | null>(null);
  const bottom = useRef<HTMLDivElement>(null);

  const provider = useQuery({
    queryKey: ["ai-provider-active"],
    queryFn: () => api<{ name: string; model: string } | null>("/ai/providers/active"),
  });

  // Asset chats: show the most recent shared conversation for this asset.
  const assetConvs = useQuery({
    queryKey: ["ai-conversations", "asset", assetId],
    queryFn: () => api<AIConversation[]>(`/ai/conversations?scope=asset&asset_id=${assetId}`),
    enabled: !!assetId,
  });
  const activeId = assetId ? (assetConvId ?? assetConvs.data?.[0]?.id ?? null) : (conversationId ?? null);

  const conv = useQuery({
    queryKey: ["ai-conversation", activeId],
    queryFn: () => api<AIConversationDetail>(`/ai/conversations/${activeId}`),
    enabled: !!activeId,
  });

  const send = useMutation({
    mutationFn: async (content: string) => {
      let id = activeId;
      if (!id) {
        const created = await api<AIConversation>("/ai/conversations", { method: "POST", json: { asset_id: assetId ?? null } });
        id = created.id;
        if (assetId) setAssetConvId(id);
        onConversationCreated?.(id);
      }
      await api(`/ai/conversations/${id}/messages`, { method: "POST", json: { content } });
      return id;
    },
    onMutate: (content) => setPending(content),
    onSettled: (id) => {
      setPending(null);
      qc.invalidateQueries({ queryKey: ["ai-conversation", id] });
      qc.invalidateQueries({ queryKey: ["ai-conversations"] });
    },
    onError: (e) => toast.error(e.message),
  });

  const messages = useMemo(() => conv.data?.messages ?? [], [conv.data]);
  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [messages.length, pending]);

  const mention = useMention(assetId ? "" : text);
  const submit = (value = text) => {
    const v = value.trim();
    if (!v || send.isPending) return;
    setText("");
    send.mutate(v);
  };
  const suggestions = assetId ? ASSET_SUGGESTIONS : GLOBAL_SUGGESTIONS;

  if (provider.data === null) {
    return (
      <div className={cn("rounded-xl border border-dashed p-6 text-center text-sm text-muted-foreground", className)}>
        Belum ada provider AI yang aktif. ADMIN/SECURITY dapat menambahkannya di{" "}
        <Link href="/settings/ai" className="text-primary underline">Pengaturan AI</Link>.
      </div>
    );
  }

  return (
    <div className={cn("flex min-h-0 flex-col", className)}>
      {assetId && (
        <div className="mb-2 flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>
            {assetConvs.data?.length ? `${assetConvs.data.length} percakapan tersimpan untuk asset ini (terlihat oleh tim)` : "Riwayat chat asset ini terlihat oleh tim."}
          </span>
          {!!activeId && (
            <Button variant="ghost" size="xs" onClick={() => {
              api<AIConversation>("/ai/conversations", { method: "POST", json: { asset_id: assetId } }).then((c) => {
                setAssetConvId(c.id);
                qc.invalidateQueries({ queryKey: ["ai-conversations", "asset", assetId] });
              });
            }}>
              <Plus /> Percakapan baru
            </Button>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
        {!messages.length && !pending && (
          <div className="py-4">
            <p className="mb-3 text-sm text-muted-foreground">
              Tanyakan kondisi {assetId ? "asset ini" : "server & website Anda"}. AI membaca data assessment dan temuan
              (read-only) dan tidak menjalankan apa pun tanpa konfirmasi Anda.
              {!assetId && " Sebut asset tertentu dengan @nama."}
            </p>
            <div className="flex flex-wrap gap-2">
              {suggestions.map((s) => (
                <button key={s} onClick={() => submit(s)}
                  className="rounded-full border px-3 py-1 text-left text-xs hover:bg-muted">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m) => <MessageBubble key={m.id} m={m} />)}
        {pending && (
          <>
            <div className="flex justify-end">
              <div className="max-w-[85%] rounded-2xl rounded-br-sm bg-primary/80 px-3.5 py-2 text-sm whitespace-pre-wrap text-primary-foreground">
                {pending}
              </div>
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> AI sedang mengambil data dan menganalisis…
            </div>
          </>
        )}
        <div ref={bottom} />
      </div>

      <div className="relative mt-3">
        {mention.active && mention.options.length > 0 && (
          <div className="absolute bottom-full z-10 mb-1 w-72 overflow-hidden rounded-lg border bg-popover shadow-md">
            {mention.options.map((a) => (
              <button key={a.id} className="flex w-full justify-between px-3 py-1.5 text-left text-sm hover:bg-muted"
                onClick={() => setText(text.replace(/@[\w.-]*$/, `@${a.name} `))}>
                <span className="truncate">{a.name}</span>
                <span className="text-xs text-muted-foreground">{a.asset_type}</span>
              </button>
            ))}
          </div>
        )}
        <div className="flex items-end gap-2 rounded-xl border bg-background p-2 focus-within:ring-2 focus-within:ring-ring/40">
          <Textarea
            rows={2}
            value={text}
            placeholder={assetId ? "Tanya tentang asset ini…" : "Tanya tentang server/website… (ketik @ untuk menyebut asset)"}
            className="max-h-40 min-h-10 resize-none border-0 shadow-none focus-visible:ring-0"
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                submit();
              }
            }}
          />
          <Button size="icon" aria-label="Kirim" onClick={() => submit()} disabled={!text.trim() || send.isPending}>
            <SendHorizontal />
          </Button>
        </div>
        <p className="mt-1 text-[11px] text-muted-foreground">
          {provider.data ? `${provider.data.name} · ${provider.data.model}` : ""} · Enter kirim, Shift+Enter baris baru.
          Jawaban AI bisa keliru — cek evidence-nya.
        </p>
      </div>
    </div>
  );
}
