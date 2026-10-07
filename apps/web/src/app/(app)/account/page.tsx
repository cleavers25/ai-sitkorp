"use client";

import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { Field, FormError } from "@/components/form";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";

export default function AccountPage() {
  const router = useRouter();
  const { me } = useMe();
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm: "" });
  const [localError, setLocalError] = useState<string | null>(null);

  const change = useMutation({
    mutationFn: () =>
      api("/auth/change-password", {
        method: "POST",
        json: { current_password: form.current_password, new_password: form.new_password },
      }),
    onSuccess: () => {
      toast.success("Password diganti. Silakan login kembali.");
      router.replace("/login");
    },
  });

  return (
    <>
      <PageHeader title="Akun saya" description={me ? `${me.full_name} · ${me.email} · ${me.role}` : undefined} />
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle className="text-sm">Ganti password</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (form.new_password !== form.confirm) {
                setLocalError("Konfirmasi password tidak sama.");
                return;
              }
              setLocalError(null);
              change.mutate();
            }}
          >
            <Field label="Password saat ini" htmlFor="a-cur">
              <Input id="a-cur" type="password" required autoComplete="current-password"
                value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} />
            </Field>
            <Field label="Password baru" htmlFor="a-new"
              hint="Minimal 12 karakter, campuran minimal 3 dari: huruf kecil, huruf besar, angka, simbol.">
              <Input id="a-new" type="password" required autoComplete="new-password"
                value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} />
            </Field>
            <Field label="Ulangi password baru" htmlFor="a-conf">
              <Input id="a-conf" type="password" required autoComplete="new-password"
                value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} />
            </Field>
            <FormError message={localError ?? change.error?.message ?? null} />
            <Button type="submit" disabled={change.isPending}>Ganti password</Button>
            <p className="text-xs text-muted-foreground">Setelah password diganti, semua sesi Anda di perangkat lain ikut berakhir.</p>
          </form>
        </CardContent>
      </Card>
    </>
  );
}
