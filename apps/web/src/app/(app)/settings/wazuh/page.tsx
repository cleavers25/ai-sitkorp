"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Plug, RefreshCw, XCircle } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Field, FormError, NativeSelect } from "@/components/form";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AssetRef, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

interface WazuhSettings {
  enabled: boolean;
  api_url: string | null;
  api_user: string | null;
  has_api_password: boolean;
  indexer_url: string | null;
  indexer_user: string | null;
  has_indexer_password: boolean;
  verify_tls: boolean;
  has_ca_cert: boolean;
  min_alert_level: number;
  last_sync_at: string | null;
  last_sync_ok: boolean | null;
  last_sync_error: string | null;
}

interface WazuhAgent {
  agent_id: string;
  name: string;
  ip: string | null;
  status: string | null;
  os_name: string | null;
  os_version: string | null;
  version: string | null;
  last_keepalive: string | null;
  groups: string[];
  server_id: string | null;
  server_name: string | null;
  mapping: "AUTO" | "MANUAL" | "NONE";
}

type TestPart = { ok: boolean; version?: string; cluster?: string; error?: string };

const AGENT_STATUS: Record<string, string> = {
  active: "text-emerald-700 dark:text-emerald-400",
  disconnected: "text-red-700 dark:text-red-400",
  pending: "text-amber-700 dark:text-amber-400",
  never_connected: "text-muted-foreground",
  removed: "text-muted-foreground line-through",
};

function SettingsForm({ s }: { s: WazuhSettings }) {
  const qc = useQueryClient();
  const [f, setF] = useState({
    enabled: s.enabled,
    api_url: s.api_url ?? "",
    api_user: s.api_user ?? "",
    api_password: "",
    indexer_url: s.indexer_url ?? "",
    indexer_user: s.indexer_user ?? "",
    indexer_password: "",
    verify_tls: s.verify_tls,
    ca_cert: "",
    keep_ca: s.has_ca_cert,
    min_alert_level: String(s.min_alert_level),
  });
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const [test, setTest] = useState<{ api?: TestPart; indexer?: TestPart } | null>(null);

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        enabled: f.enabled,
        api_url: f.api_url.trim() || null,
        api_user: f.api_user.trim() || null,
        indexer_url: f.indexer_url.trim() || null,
        indexer_user: f.indexer_user.trim() || null,
        verify_tls: f.verify_tls,
        min_alert_level: Number(f.min_alert_level),
      };
      if (f.api_password) body.api_password = f.api_password;
      if (f.indexer_password) body.indexer_password = f.indexer_password;
      // Omitting ca_cert keeps the stored CA; null clears it.
      if (f.ca_cert.trim()) body.ca_cert = f.ca_cert.trim();
      else if (!f.keep_ca) body.ca_cert = null;
      return api<WazuhSettings>("/integrations/wazuh", { method: "PUT", json: body });
    },
    onSuccess: (data) => {
      qc.setQueryData(["wazuh-settings"], data);
      setF((prev) => ({ ...prev, api_password: "", indexer_password: "", ca_cert: "", keep_ca: data.has_ca_cert }));
      toast.success("Pengaturan Wazuh disimpan");
    },
  });
  const runTest = useMutation({
    mutationFn: async () => {
      await save.mutateAsync();
      return api<{ api?: TestPart; indexer?: TestPart }>("/integrations/wazuh/test", { method: "POST" });
    },
    onSuccess: setTest,
  });

  return (
    <Card>
      <CardHeader><CardTitle className="text-base">Koneksi</CardTitle></CardHeader>
      <CardContent>
        <form id="wz-form" className="grid gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <p className="text-sm font-medium sm:col-span-2">Wazuh Server API <span className="font-normal text-muted-foreground">(agent, SCA)</span></p>
          <Field label="URL API" htmlFor="wz-api" hint="Biasanya port 55000." className="sm:col-span-2">
            <Input id="wz-api" value={f.api_url} onChange={set("api_url")} placeholder="https://wazuh.kantor.local:55000" />
          </Field>
          <Field label="User API" htmlFor="wz-apiuser" hint="Sebaiknya user dengan role readonly.">
            <Input id="wz-apiuser" value={f.api_user} onChange={set("api_user")} autoComplete="off" />
          </Field>
          <Field label="Password API" htmlFor="wz-apipw" hint={s.has_api_password ? "Tersimpan. Isi hanya jika ingin mengganti." : undefined}>
            <Input id="wz-apipw" type="password" autoComplete="new-password" value={f.api_password} onChange={set("api_password")}
              placeholder={s.has_api_password ? "••••••••" : ""} />
          </Field>

          <p className="mt-2 text-sm font-medium sm:col-span-2">Wazuh Indexer <span className="font-normal text-muted-foreground">(alert, FIM, kerentanan/CVE)</span></p>
          <Field label="URL Indexer" htmlFor="wz-idx" hint="Biasanya port 9200. Kosongkan jika hanya memakai Server API." className="sm:col-span-2">
            <Input id="wz-idx" value={f.indexer_url} onChange={set("indexer_url")} placeholder="https://wazuh.kantor.local:9200" />
          </Field>
          <Field label="User Indexer" htmlFor="wz-idxuser" hint="Cukup akses baca ke wazuh-alerts-* dan wazuh-states-vulnerabilities-*.">
            <Input id="wz-idxuser" value={f.indexer_user} onChange={set("indexer_user")} autoComplete="off" />
          </Field>
          <Field label="Password Indexer" htmlFor="wz-idxpw" hint={s.has_indexer_password ? "Tersimpan. Isi hanya jika ingin mengganti." : undefined}>
            <Input id="wz-idxpw" type="password" autoComplete="new-password" value={f.indexer_password} onChange={set("indexer_password")}
              placeholder={s.has_indexer_password ? "••••••••" : ""} />
          </Field>

          <p className="mt-2 text-sm font-medium sm:col-span-2">Keamanan & ambang</p>
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input type="checkbox" checked={f.verify_tls} onChange={(e) => setF({ ...f, verify_tls: e.target.checked })} />
            Verifikasi sertifikat TLS
          </label>
          {f.verify_tls && (
            <Field
              label="CA certificate (PEM)"
              htmlFor="wz-ca"
              className="sm:col-span-2"
              hint={f.keep_ca ? "CA tersimpan dipakai. Tempel CA baru untuk mengganti." : "Wazuh default memakai sertifikat self-signed: tempel root-ca.pem di sini agar verifikasi tetap aktif."}
            >
              <Textarea id="wz-ca" rows={3} className="font-mono text-xs" value={f.ca_cert} onChange={set("ca_cert")}
                placeholder="-----BEGIN CERTIFICATE-----" />
            </Field>
          )}
          {f.verify_tls && s.has_ca_cert && (
            <label className="-mt-2 flex items-center gap-2 text-sm sm:col-span-2">
              <input type="checkbox" checked={!f.keep_ca} onChange={(e) => setF({ ...f, keep_ca: !e.target.checked })} />
              Hapus CA tersimpan
            </label>
          )}
          <Field label="Level alert minimum" htmlFor="wz-lvl" hint="Alert di bawah level ini diabaikan (≥13 CRITICAL, ≥10 HIGH, ≥7 MEDIUM).">
            <NativeSelect id="wz-lvl" value={f.min_alert_level} onChange={set("min_alert_level")}>
              {Array.from({ length: 13 }, (_, i) => i + 3).map((l) => <option key={l} value={l}>Level {l}{l === 10 ? " (disarankan)" : ""}</option>)}
            </NativeSelect>
          </Field>
          <label className="flex items-center gap-2 self-end pb-1.5 text-sm">
            <input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />
            Aktifkan integrasi
          </label>
          <div className="sm:col-span-2"><FormError message={save.error?.message ?? runTest.error?.message ?? null} /></div>
        </form>

        {test && (
          <div className="mt-4 grid gap-2 rounded-lg border p-3 text-sm">
            {(["api", "indexer"] as const).map((k) => {
              const t = test[k];
              if (!t) return null;
              return (
                <p key={k} className={cn("flex items-start gap-2", t.ok ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400")}>
                  {t.ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" /> : <XCircle className="mt-0.5 size-4 shrink-0" />}
                  <span>
                    <b>{k === "api" ? "Server API" : "Indexer"}</b>:{" "}
                    {t.ok ? `terhubung${t.version ? ` · versi ${t.version}` : ""}${t.cluster ? ` · cluster ${t.cluster}` : ""}` : t.error}
                  </span>
                </p>
              );
            })}
          </div>
        )}

        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <Button variant="outline" onClick={() => runTest.mutate()} disabled={runTest.isPending || !f.api_url}>
            <Plug /> {runTest.isPending ? "Menguji…" : "Simpan & tes koneksi"}
          </Button>
          <Button type="submit" form="wz-form" disabled={save.isPending}>Simpan</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function AgentTable({ enabled }: { enabled: boolean }) {
  const qc = useQueryClient();
  const agents = useQuery({ queryKey: ["wazuh-agents"], queryFn: () => api<WazuhAgent[]>("/integrations/wazuh/agents") });
  const servers = useQuery({
    queryKey: ["assets", "servers-picker"],
    queryFn: () => api<Page<AssetRef>>("/assets?asset_type=SERVER&limit=500"),
  });
  const sync = useMutation({
    mutationFn: () => api<{ agents: number; mapped: number }>("/integrations/wazuh/sync", { method: "POST" }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["wazuh-agents"] });
      qc.invalidateQueries({ queryKey: ["wazuh-settings"] });
      toast.success(`${r.agents} agent disinkron, ${r.mapped} terpetakan ke server`);
    },
    onError: (e) => toast.error(e.message),
  });
  const map = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      api(`/integrations/wazuh/agents/${id}`, {
        method: "PATCH",
        json: value === "__auto" ? { auto: true } : { server_id: value || null },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["wazuh-agents"] }),
    onError: (e) => toast.error(e.message),
  });
  const list = agents.data ?? [];
  const serverList = (servers.data?.items ?? []).filter((a) => a.asset_type === "SERVER");

  return (
    <Card className="mt-6">
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
        <CardTitle className="text-base">Agent & pemetaan server</CardTitle>
        <Button variant="outline" size="sm" onClick={() => sync.mutate()} disabled={sync.isPending || !enabled}>
          <RefreshCw className={cn(sync.isPending && "animate-spin")} /> Sinkron agent
        </Button>
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-sm text-muted-foreground">
          Agent dipetakan otomatis ke server bila nama/IP agent sama dengan hostname atau nama server. Server yang terpetakan akan
          mendapat cek tambahan dari Wazuh (alert, FIM, CVE, SCA) di setiap assessment. Sinkron otomatis berjalan tiap 15 menit.
        </p>
        {!list.length ? (
          <p className="text-sm text-muted-foreground">
            {enabled ? "Belum ada agent. Tekan \"Sinkron agent\"." : "Aktifkan & simpan integrasi terlebih dahulu, lalu sinkron agent."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted-foreground">
                <tr className="border-b">
                  <th className="py-2 pr-3 font-medium">ID</th>
                  <th className="py-2 pr-3 font-medium">Agent</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">OS</th>
                  <th className="py-2 pr-3 font-medium">Server</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {list.map((a) => (
                  <tr key={a.agent_id}>
                    <td className="py-2 pr-3 font-mono text-xs">{a.agent_id}</td>
                    <td className="py-2 pr-3">
                      <p className="font-medium">{a.name}</p>
                      <p className="text-xs text-muted-foreground">{a.ip}{a.version ? ` · ${a.version}` : ""}</p>
                    </td>
                    <td className={cn("py-2 pr-3 text-xs", AGENT_STATUS[a.status ?? ""] ?? "")}>{a.status ?? "—"}</td>
                    <td className="py-2 pr-3 text-xs text-muted-foreground">{[a.os_name, a.os_version].filter(Boolean).join(" ") || "—"}</td>
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-2">
                        <NativeSelect
                          className="w-48"
                          aria-label={`Server untuk agent ${a.name}`}
                          value={a.server_id ?? ""}
                          disabled={map.isPending}
                          onChange={(e) => map.mutate({ id: a.agent_id, value: e.target.value })}
                        >
                          <option value="">— tidak dipetakan —</option>
                          {serverList.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                          <option value="__auto">↻ Otomatis (nama/IP)</option>
                        </NativeSelect>
                        <span className="text-[11px] text-muted-foreground">{a.mapping === "AUTO" ? (a.server_id ? "otomatis" : "otomatis · tidak cocok") : a.mapping === "MANUAL" ? "manual" : ""}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function WazuhSettingsPage() {
  const settings = useQuery({ queryKey: ["wazuh-settings"], queryFn: () => api<WazuhSettings>("/integrations/wazuh") });
  const s = settings.data;

  return (
    <>
      <PageHeader
        title="Integrasi Wazuh"
        description="Baca data dari Wazuh 4.x (read-only): alert level tinggi, perubahan file (FIM), kerentanan paket (CVE), dan skor SCA. Data masuk ke assessment, notifikasi, dan dapat ditanyakan ke AI Assistant."
      />
      {s && (
        <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
          <span className={cn("font-medium", s.enabled ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground")}>
            {s.enabled ? "● Aktif" : "○ Nonaktif"}
          </span>
          {s.last_sync_at && (
            <span className={cn("text-xs", s.last_sync_ok ? "text-muted-foreground" : "text-red-700 dark:text-red-400")}>
              Sinkron terakhir {formatDateTime(s.last_sync_at)}{s.last_sync_ok ? "" : `: gagal (${s.last_sync_error})`}
            </span>
          )}
        </div>
      )}
      {s && <SettingsForm s={s} />}
      {s && <AgentTable enabled={s.enabled} />}
    </>
  );
}
