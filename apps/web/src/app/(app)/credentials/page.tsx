"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { Field, FormError, NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useMe } from "@/hooks/use-me";
import { api, compact } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Credential, CredentialKind } from "@/lib/types";

const KIND_LABEL: Record<CredentialKind, string> = {
  SSH_PRIVATE_KEY: "SSH private key",
  SSH_PASSWORD: "SSH password",
  API_KEY: "API key",
};

/** Secret inputs shared by create and rotate. Values only ever travel browser → API. */
function SecretFields({
  kind,
  secret,
  setSecret,
}: {
  kind: CredentialKind;
  secret: Record<string, string>;
  setSecret: (s: Record<string, string>) => void;
}) {
  const set = (k: string) => (e: { target: { value: string } }) => setSecret({ ...secret, [k]: e.target.value });
  if (kind === "SSH_PRIVATE_KEY")
    return (
      <>
        <Field label="Private key (OpenSSH / PEM)" htmlFor="c-key" className="sm:col-span-2"
          hint="Disimpan terenkripsi (AES-256-GCM) dan tidak akan pernah ditampilkan lagi.">
          <Textarea id="c-key" required rows={6} className="font-mono text-xs" spellCheck={false} autoComplete="off"
            value={secret.private_key ?? ""} onChange={set("private_key")}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
        </Field>
        <Field label="Passphrase (opsional)" htmlFor="c-pass" className="sm:col-span-2">
          <Input id="c-pass" type="password" autoComplete="off" value={secret.passphrase ?? ""} onChange={set("passphrase")} />
        </Field>
      </>
    );
  if (kind === "SSH_PASSWORD")
    return (
      <Field label="Password" htmlFor="c-pw" className="sm:col-span-2"
        hint="Disarankan memakai SSH key. Password hanya bila benar-benar diperlukan.">
        <Input id="c-pw" type="password" required autoComplete="new-password" value={secret.password ?? ""} onChange={set("password")} />
      </Field>
    );
  return (
    <Field label="API key" htmlFor="c-api" className="sm:col-span-2">
      <Input id="c-api" type="password" required autoComplete="off" value={secret.api_key ?? ""} onChange={set("api_key")} />
    </Field>
  );
}

function CreateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<CredentialKind>("SSH_PRIVATE_KEY");
  const [meta, setMeta] = useState({ name: "", username: "", access_scope: "", description: "" });
  const [secret, setSecret] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: () =>
      api<Credential>("/credentials", { method: "POST", json: { kind, ...compact(meta), ...compact(secret) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["credentials"] });
      toast.success("Credential disimpan");
      setSecret({});
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Tambah credential</DialogTitle>
          <DialogDescription>Hanya metadata yang bisa dilihat kembali. Secret tidak pernah dikirim balik ke browser.</DialogDescription>
        </DialogHeader>
        <form id="cred-form" className="grid gap-4 sm:grid-cols-2" autoComplete="off"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Nama" htmlFor="c-name">
            <Input id="c-name" required value={meta.name} onChange={(e) => setMeta({ ...meta, name: e.target.value })} placeholder="deploy-key-prod" />
          </Field>
          <Field label="Jenis" htmlFor="c-kind">
            <NativeSelect id="c-kind" value={kind} onChange={(e) => { setKind(e.target.value as CredentialKind); setSecret({}); }}>
              {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
          </Field>
          {kind !== "API_KEY" && (
            <Field label="Username" htmlFor="c-user">
              <Input id="c-user" value={meta.username} onChange={(e) => setMeta({ ...meta, username: e.target.value })} placeholder="deploy" />
            </Field>
          )}
          <Field label="Scope akses" htmlFor="c-scope" className={kind === "API_KEY" ? "sm:col-span-2" : ""}>
            <Input id="c-scope" value={meta.access_scope} onChange={(e) => setMeta({ ...meta, access_scope: e.target.value })} placeholder="web servers (read-only)" />
          </Field>
          <SecretFields kind={kind} secret={secret} setSecret={setSecret} />
          <Field label="Deskripsi" htmlFor="c-desc" className="sm:col-span-2">
            <Input id="c-desc" value={meta.description} onChange={(e) => setMeta({ ...meta, description: e.target.value })} />
          </Field>
          <div className="sm:col-span-2"><FormError message={save.error?.message ?? null} /></div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Batal</Button>
          <Button type="submit" form="cred-form" disabled={save.isPending}>{save.isPending ? "Menyimpan…" : "Simpan"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RotateDialog({ cred, onClose }: { cred: Credential; onClose: () => void }) {
  const qc = useQueryClient();
  const [secret, setSecret] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: () => api<Credential>(`/credentials/${cred.id}/secret`, { method: "PUT", json: compact(secret) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["credentials"] });
      toast.success("Secret dirotasi");
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Rotasi secret: {cred.name}</DialogTitle>
          <DialogDescription>Secret lama langsung diganti. Server yang memakai credential ini otomatis ikut memakai secret baru.</DialogDescription>
        </DialogHeader>
        <form id="rotate-form" className="grid gap-4 sm:grid-cols-2" autoComplete="off"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <SecretFields kind={cred.kind} secret={secret} setSecret={setSecret} />
          <div className="sm:col-span-2"><FormError message={save.error?.message ?? null} /></div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="rotate-form" disabled={save.isPending}>Rotasi</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function CredentialsPage() {
  const qc = useQueryClient();
  const { can } = useMe();
  const [creating, setCreating] = useState(false);
  const [rotating, setRotating] = useState<Credential | null>(null);
  const [deleting, setDeleting] = useState<Credential | null>(null);
  const manage = can("credential:manage");

  const { data, isLoading } = useQuery({ queryKey: ["credentials"], queryFn: () => api<Credential[]>("/credentials") });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/credentials/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["credentials"] });
      toast.success("Credential dihapus");
      setDeleting(null);
    },
    onError: (e) => {
      toast.error(e.message);
      setDeleting(null);
    },
  });

  return (
    <>
      <PageHeader
        title="Credential"
        description="Referensi credential untuk akses server. Secret disimpan terenkripsi dan tidak bisa dibaca kembali."
        actions={manage && <Button onClick={() => setCreating(true)}><Plus /> Tambah credential</Button>}
      />

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.length ? (
        <EmptyState title="Belum ada credential">Tambahkan SSH key untuk mulai menghubungkan server.</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nama</TableHead>
                <TableHead>Jenis</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Fingerprint</TableHead>
                <TableHead>Rotasi terakhir</TableHead>
                {manage && <TableHead className="text-right">Aksi</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    <span className="flex items-center gap-2 font-medium"><KeyRound className="size-3.5 text-muted-foreground" />{c.name}</span>
                    {c.access_scope && <p className="text-xs text-muted-foreground">{c.access_scope}</p>}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{KIND_LABEL[c.kind]}</TableCell>
                  <TableCell>{c.username ?? "—"}</TableCell>
                  <TableCell className="max-w-56 truncate font-mono text-xs">{c.public_fingerprint ?? "—"}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDateTime(c.last_rotated_at ?? c.created_at)}</TableCell>
                  {manage && (
                    <TableCell className="text-right">
                      <Button size="icon-sm" variant="ghost" aria-label="Rotasi secret" title="Rotasi secret" onClick={() => setRotating(c)}><RefreshCw /></Button>
                      <Button size="icon-sm" variant="ghost" aria-label="Hapus" title="Hapus" onClick={() => setDeleting(c)}><Trash2 /></Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {creating && <CreateDialog open={creating} onOpenChange={setCreating} />}
      {rotating && <RotateDialog cred={rotating} onClose={() => setRotating(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Hapus credential ${deleting?.name}?`}
        description="Secret akan dihapus permanen. Credential yang masih dipakai server tidak bisa dihapus."
        confirmLabel="Hapus"
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        pending={remove.isPending}
      />
    </>
  );
}
