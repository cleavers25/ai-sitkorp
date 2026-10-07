"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ExternalLink, Pencil, Trash2, Sparkles } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { toast } from "sonner";

import { AssessmentPanel } from "@/components/assessment-panel";
import { ChatPanel } from "@/components/chat-panel";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { MemoryCard } from "@/components/memory-card";
import { CriticalityText, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { WebsiteFormDialog } from "@/components/website-form-dialog";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Website } from "@/lib/types";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[9rem_1fr] gap-2 py-1.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children || "—"}</dd>
    </div>
  );
}

export default function WebsiteDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const { can } = useMe();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const website = useQuery({ queryKey: ["website", id], queryFn: () => api<Website>(`/websites/${id}`) });
  const onFinished = useCallback(() => {
    qc.invalidateQueries({ queryKey: ["website", id] });
    qc.invalidateQueries({ queryKey: ["websites"] });
  }, [qc, id]);

  const remove = useMutation({
    mutationFn: () => api(`/websites/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Website dihapus");
      qc.invalidateQueries({ queryKey: ["websites"] });
      qc.invalidateQueries({ queryKey: ["servers"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      router.replace("/websites");
    },
    onError: (e) => toast.error(e.message),
  });

  if (website.isLoading) return <p className="text-sm text-muted-foreground">Memuat…</p>;
  if (!website.data) return <p className="text-sm text-muted-foreground">Website tidak ditemukan.</p>;
  const w = website.data;

  return (
    <>
      <Link href="/websites" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> Semua website
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight">{w.name}</h1>
          <a href={w.url} target="_blank" rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            {w.url} <ExternalLink className="size-3" />
          </a>
          <div className="mt-2"><StatusBadge status={w.status} /></div>
        </div>
        {can("asset:manage") && (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setEditing(true)}>
              <Pencil /> Ubah
            </Button>
            <Button variant="destructive" onClick={() => setDeleting(true)}>
              <Trash2 /> Hapus
            </Button>
          </div>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm">Informasi</CardTitle></CardHeader>
          <CardContent>
            <dl className="divide-y">
              <Row label="Domain">{w.domain}</Row>
              <Row label="Kritikalitas"><CriticalityText value={w.criticality} /></Row>
              <Row label="Environment">{w.environment}</Row>
              <Row label="Owner">{w.owner}</Row>
              <Row label="Deskripsi">{w.description}</Row>
              <Row label="Dibuat">{formatDateTime(w.created_at)}</Row>
            </dl>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Hosting</CardTitle></CardHeader>
          <CardContent>
            <dl className="divide-y">
              <Row label="Server">
                {w.server && (
                  <Link href={`/servers/${w.server.id}`} className="hover:underline">
                    {w.server.name} <span className="font-mono text-xs text-muted-foreground">({w.server.hostname})</span>
                  </Link>
                )}
              </Row>
              <Row label="Aplikasi">{w.application}</Row>
              <Row label="Web server">{w.web_server}</Row>
              <Row label="Runtime">{w.runtime}</Row>
              <Row label="Document root">{w.document_root && <code className="font-mono text-xs">{w.document_root}</code>}</Row>
            </dl>
          </CardContent>
        </Card>
      </div>

      {(!w.document_root || !w.server) && (
        <p className="mt-4 rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200">
          Scan malware file (heuristik, ClamAV, YARA) butuh website terhubung ke server yang punya credential SSH dan
          document root terisi. Tanpa itu, assessment hanya menjalankan check dari luar (HTTP, SSL, header, file
          terekspos, konten).
        </p>
      )}

      <AssessmentPanel assetId={w.id} onFinished={onFinished} />
      <MemoryCard assetId={w.id} />

      <Card className="mt-6">
        <CardHeader><CardTitle className="flex items-center gap-2 text-sm"><Sparkles className="size-4" /> Chat AI tentang {w.name}</CardTitle></CardHeader>
        <CardContent>
          <ChatPanel assetId={w.id} className="h-[34rem]" />
        </CardContent>
      </Card>


      {editing && <WebsiteFormDialog open={editing} onOpenChange={setEditing} website={w} />}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Hapus website ${w.name}?`}
        description="Data website dihapus dari inventory. Tindakan ini tercatat di audit log."
        confirmLabel="Hapus website"
        onConfirm={() => remove.mutate()}
        pending={remove.isPending}
      />
    </>
  );
}
