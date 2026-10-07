"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { Field, FormError } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { Me } from "@/lib/types";

function safeNext(next: string | null): string {
  // Only allow same-site relative paths, never "//host" or absolute URLs.
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const qc = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const login = useMutation({
    mutationFn: () => api<{ user: Me }>("/auth/login", { method: "POST", json: { email, password } }),
    onSuccess: (data) => {
      qc.setQueryData(["me"], data.user);
      router.replace(safeNext(params.get("next")));
    },
  });

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        login.mutate();
      }}
    >
      <Field label="Email" htmlFor="email">
        <Input id="email" type="email" autoComplete="username" required autoFocus
          value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Password" htmlFor="password">
        <Input id="password" type="password" autoComplete="current-password" required
          value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <FormError
        message={login.error ? "Email atau password salah, atau akun sedang dikunci sementara." : null}
      />
      <Button type="submit" size="lg" disabled={login.isPending}>
        {login.isPending ? "Memproses…" : "Masuk"}
      </Button>
    </form>
  );
}

export default function LoginPage() {
  return (
    <div className="grid min-h-dvh place-items-center bg-muted/40 px-4">
      <div className="w-full max-w-sm rounded-2xl border bg-card p-8 shadow-sm">
        <div className="mb-6 flex items-center gap-2.5">
          <ShieldCheck className="size-7 text-primary" />
          <div>
            <h1 className="font-semibold leading-tight">AI Infra Assistant</h1>
            <p className="text-xs text-muted-foreground">Masuk untuk melanjutkan</p>
          </div>
        </div>
        <Suspense>
          <LoginForm />
        </Suspense>
      </div>
    </div>
  );
}
