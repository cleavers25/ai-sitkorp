"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Field, FormError, NativeSelect } from "@/components/form";
import { PageHeader } from "@/components/page-header";
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
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { ROLES, type Role, type User } from "@/lib/types";

const ROLE_HINT: Record<Role, string> = {
  ADMIN: "Akses penuh, termasuk kelola user",
  INFRA: "Kelola asset & credential, tes koneksi",
  SECURITY: "Lihat asset & audit, jalankan tool aman, konfigurasi AI",
  OPERATOR: "Lihat asset, jalankan tool aman",
  VIEWER: "Hanya melihat",
  AUDITOR: "Melihat asset & audit log",
};

const PASSWORD_HINT = "Minimal 12 karakter, campuran minimal 3 dari: huruf kecil, huruf besar, angka, simbol.";

function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({ email: "", full_name: "", role: "VIEWER" as Role, password: "" });
  const save = useMutation({
    mutationFn: () => api<User>("/users", { method: "POST", json: form }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      toast.success("User dibuat");
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Tambah user</DialogTitle>
          <DialogDescription>Berikan password awal secara aman; minta user menggantinya setelah login.</DialogDescription>
        </DialogHeader>
        <form id="user-form" className="grid gap-4" autoComplete="off" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Nama lengkap" htmlFor="u-name">
            <Input id="u-name" required value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          </Field>
          <Field label="Email" htmlFor="u-email">
            <Input id="u-email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </Field>
          <Field label="Role" htmlFor="u-role" hint={ROLE_HINT[form.role]}>
            <NativeSelect id="u-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {ROLES.map((r) => <option key={r}>{r}</option>)}
            </NativeSelect>
          </Field>
          <Field label="Password awal" htmlFor="u-pw" hint={PASSWORD_HINT}>
            <Input id="u-pw" type="password" required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </Field>
          <FormError message={save.error?.message ?? null} />
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="user-form" disabled={save.isPending}>Simpan</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ResetPasswordDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const [pw, setPw] = useState("");
  const save = useMutation({
    mutationFn: () => api(`/users/${user.id}/reset-password`, { method: "POST", json: { new_password: pw } }),
    onSuccess: () => {
      toast.success("Password di-reset; semua sesi user tersebut dikeluarkan");
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset password {user.email}</DialogTitle>
          <DialogDescription>Semua sesi aktif user ini akan diakhiri, dan kunci akun (lockout) dibuka.</DialogDescription>
        </DialogHeader>
        <form id="reset-form" className="grid gap-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Password baru" htmlFor="r-pw" hint={PASSWORD_HINT}>
            <Input id="r-pw" type="password" required autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
          </Field>
          <FormError message={save.error?.message ?? null} />
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="reset-form" disabled={save.isPending}>Reset</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function UsersPage() {
  const qc = useQueryClient();
  const { me } = useMe();
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<User | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/users") });

  const update = useMutation({
    mutationFn: ({ id, changes }: { id: string; changes: Partial<Pick<User, "role" | "is_active">> }) =>
      api<User>(`/users/${id}`, { method: "PATCH", json: changes }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      toast.success("User diperbarui");
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <>
      <PageHeader
        title="User"
        description="Kelola akun dan role. Perubahan role langsung mengakhiri sesi user tersebut."
        actions={<Button onClick={() => setCreating(true)}><Plus /> Tambah user</Button>}
      />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Login terakhir</TableHead>
                <TableHead className="text-right">Aksi</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.map((u) => (
                <TableRow key={u.id} className={u.is_active ? "" : "opacity-60"}>
                  <TableCell>
                    <p className="font-medium">{u.full_name}{u.id === me?.id && <span className="ml-1 text-xs text-muted-foreground">(Anda)</span>}</p>
                    <p className="text-xs text-muted-foreground">{u.email}</p>
                  </TableCell>
                  <TableCell>
                    <NativeSelect className="w-32" aria-label={`Role ${u.email}`} value={u.role}
                      onChange={(e) => update.mutate({ id: u.id, changes: { role: e.target.value as Role } })}>
                      {ROLES.map((r) => <option key={r}>{r}</option>)}
                    </NativeSelect>
                  </TableCell>
                  <TableCell>
                    <Button size="sm" variant="outline" onClick={() => update.mutate({ id: u.id, changes: { is_active: !u.is_active } })}>
                      {u.is_active ? "Aktif — nonaktifkan" : "Nonaktif — aktifkan"}
                    </Button>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{formatDateTime(u.last_login_at)}</TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="ghost" onClick={() => setResetting(u)}><KeyRound /> Reset password</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {creating && <CreateUserDialog onClose={() => setCreating(false)} />}
      {resetting && <ResetPasswordDialog user={resetting} onClose={() => setResetting(null)} />}
    </>
  );
}
