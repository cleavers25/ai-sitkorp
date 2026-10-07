"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Pencil, PlugZap, RotateCcw, Trash2, Sparkles } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { toast } from "sonner";

import { AssessmentPanel } from "@/components/assessment-panel";
import { ChatPanel } from "@/components/chat-panel";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { MemoryCard } from "@/components/memory-card";
import { ServerFormDialog } from "@/components/server-form-dialog";
import { ConnectivityBadge, CriticalityText, StatusBadge } from "@/components/status";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Credential, Page, Server, Website } from "@/lib/types";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[9rem_1fr] gap-2 py-1.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children ?? "—"}</dd>
    </div>
  );
}

export default function ServerDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const { can } = useMe();
  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<"delete" | "reset" | null>(null);

  const server = useQuery({
    queryKey: ["server", id],
    queryFn: () => api<Server>(`/servers/${id}`),
    // Poll while a connectivity job is running.
    refetchInterval: (q) => (q.state.data?.connectivity_status === "PENDING" ? 2000 : false),
  });
  const websites = useQuery({
    queryKey: ["websites", { server_id: id }],
    queryFn: () => api<Page<Website>>(`/websites?server_id=${id}&limit=200`),
  });
  const credential = useQuery({
    queryKey: ["credential", server.data?.credential_id],
    queryFn: () => api<Credential>(`/credentials/${server.data!.credential_id}`),
    enabled: !!server.data?.credential_id && can("credential:view"),
  });

  const refresh = useCallback((s?: Server) => {
    if (s) qc.setQueryData(["server", id], s);
    else qc.invalidateQueries({ queryKey: ["server", id] });
    qc.invalidateQueries({ queryKey: ["servers"] });
    qc.invalidateQueries({ queryKey: ["dashboard"] });
  }, [qc, id]);

  const testConn = useMutation({
    mutationFn: () => api(`/servers/${id}/test-connection`, { method: "POST" }),
    onSuccess: () => {
      toast.info("Tes koneksi dijalankan di background");
      refresh();
    },
    onError: (e) => toast.error(e.message),
  });
  const resetKey = useMutation({
    mutationFn: () => api<Server>(`/servers/${id}/reset-host-key`, { method: "POST" }),
    onSuccess: (s) => {
      toast.success("Host key di-reset. Tes koneksi berikutnya akan mem-pin key baru.");
      setConfirm(null);
      refresh(s);
    },
    onError: (e) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: () => api(`/servers/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast.success("Server dihapus");
      qc.invalidateQueries({ queryKey: ["servers"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      router.replace("/servers");
    },
    onError: (e) => toast.error(e.message),
  });

  if (server.isLoading) return <p className="text-sm text-muted-foreground">Memuat…</p>;
  if (!server.data) return <p className="text-sm text-muted-foreground">Server tidak ditemukan.</p>;
  const s = server.data;
  const pending = s.connectivity_status === "PENDING";

  return (
    <>
      <Link href="/servers" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> Semua server
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight">{s.name}</h1>
          <p className="mt-1 font-mono text-sm text-muted-foreground">
            {s.hostname}:{s.ssh_port}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <StatusBadge status={s.status} />
            <ConnectivityBadge status={s.connectivity_status} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {can("tool:run_safe") && (
            <Button
              onClick={() => testConn.mutate()}
              disabled={pending || testConn.isPending || !s.credential_id || s.connectivity_status === "HOST_KEY_MISMATCH"}
              title={!s.credential_id ? "Pilih credential SSH terlebih dulu" : undefined}
            >
              <PlugZap /> {pending ? "Memeriksa…" : "Tes koneksi"}
            </Button>
          )}
          {can("asset:manage") && (
            <>
              <Button variant="outline" onClick={() => setEditing(true)}>
                <Pencil /> Ubah
              </Button>
              <Button variant="destructive" onClick={() => setConfirm("delete")}>
                <Trash2 /> Hapus
              </Button>
            </>
          )}
        </div>
      </div>

      {s.connectivity_status === "HOST_KEY_MISMATCH" && (
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Host key server berubah — koneksi diblokir</AlertTitle>
          <AlertDescription>
            <p>
              Key yang dikirim server tidak sama dengan key yang di-pin ({s.host_key_fingerprint}). Ini bisa berarti
              server di-install ulang, atau ada serangan man-in-the-middle. Verifikasi fingerprint langsung di server
              (<code className="font-mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>) sebelum me-reset.
            </p>
            {can("asset:manage") && (
              <Button size="sm" variant="outline" className="mt-3" onClick={() => setConfirm("reset")}>
                <RotateCcw /> Reset host key
              </Button>
            )}
          </AlertDescription>
        </Alert>
      )}

      {s.connectivity_status === "FAILED" && s.last_connectivity_error && (
        <Alert variant="destructive" className="mb-6">
          <AlertTitle>Tes koneksi terakhir gagal</AlertTitle>
          <AlertDescription className="font-mono text-xs">{s.last_connectivity_error}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm">Informasi</CardTitle></CardHeader>
          <CardContent>
            <dl className="divide-y">
              <Row label="Kritikalitas"><CriticalityText value={s.criticality} /></Row>
              <Row label="Environment">{s.environment}</Row>
              <Row label="Owner">{s.owner}</Row>
              <Row label="Deskripsi">{s.description}</Row>
              <Row label="Dibuat">{formatDateTime(s.created_at)}</Row>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">Akses &amp; sistem</CardTitle></CardHeader>
          <CardContent>
            <dl className="divide-y">
              <Row label="Credential">
                {s.credential_id ? (credential.data?.name ?? "(terpasang)") : <span className="text-amber-700 dark:text-amber-400">Belum dipilih</span>}
              </Row>
              <Row label="Username SSH">{s.ssh_username ?? credential.data?.username}</Row>
              <Row label="Host key">
                {s.host_key_fingerprint ? <code className="font-mono text-xs">{s.host_key_fingerprint}</code> : "Belum di-pin"}
              </Row>
              <Row label="OS">{s.os_name ? `${s.os_name} ${s.os_version ?? ""}` : null}</Row>
              <Row label="Kernel">{s.kernel && <code className="font-mono text-xs">{s.kernel}</code>}</Row>
              <Row label="Tes terakhir">{formatDateTime(s.last_connectivity_check_at)}</Row>
            </dl>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader><CardTitle className="text-sm">Website di server ini ({websites.data?.total ?? 0})</CardTitle></CardHeader>
        <CardContent>
          {!websites.data?.items.length ? (
            <p className="text-sm text-muted-foreground">Belum ada website yang dihubungkan ke server ini.</p>
          ) : (
            <ul className="divide-y text-sm">
              {websites.data.items.map((w) => (
                <li key={w.id} className="flex items-center justify-between gap-3 py-2">
                  <Link href={`/websites/${w.id}`} className="font-medium hover:underline">{w.name}</Link>
                  <StatusBadge status={w.status} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <AssessmentPanel assetId={s.id} onFinished={refresh} />
      <MemoryCard assetId={s.id} />

      <Card className="mt-6">
        <CardHeader><CardTitle className="flex items-center gap-2 text-sm"><Sparkles className="size-4" /> Chat AI tentang {s.name}</CardTitle></CardHeader>
        <CardContent>
          <ChatPanel assetId={s.id} className="h-[34rem]" />
        </CardContent>
      </Card>


      {editing && <ServerFormDialog open={editing} onOpenChange={setEditing} server={s} />}
      <ConfirmDialog
        open={confirm === "delete"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Hapus server ${s.name}?`}
        description="Website yang terhubung tidak ikut terhapus, tetapi tidak lagi terhubung ke server mana pun. Tindakan ini tercatat di audit log."
        confirmLabel="Hapus server"
        onConfirm={() => remove.mutate()}
        pending={remove.isPending}
      />
      <ConfirmDialog
        open={confirm === "reset"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Reset host key?"
        description="Lakukan hanya setelah Anda memverifikasi fingerprint baru langsung di server. Tes koneksi berikutnya akan mempercayai key apa pun yang dikirim server."
        confirmLabel="Reset host key"
        onConfirm={() => resetKey.mutate()}
        pending={resetKey.isPending}
      />
    </>
  );
}
