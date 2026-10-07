"use client";

import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { ServerFormDialog } from "@/components/server-form-dialog";
import { ConnectivityBadge, CriticalityText, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import type { Page, Server } from "@/lib/types";

function ServersContent() {
  const router = useRouter();
  const params = useSearchParams();
  const { can } = useMe();
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const connectivity = params.get("connectivity") ?? "";

  const search = new URLSearchParams({ limit: "200" });
  if (q) search.set("q", q);
  if (connectivity) search.set("connectivity", connectivity);

  const { data, isLoading } = useQuery({
    queryKey: ["servers", q, connectivity],
    queryFn: () => api<Page<Server>>(`/servers?${search}`),
  });

  return (
    <>
      <PageHeader
        title="Server"
        description="Server yang dikelola beserta status akses SSH-nya."
        actions={
          can("asset:manage") && (
            <Button onClick={() => setCreating(true)}>
              <Plus /> Tambah server
            </Button>
          )
        }
      />

      <div className="mb-4 flex flex-wrap gap-2">
        <Input className="max-w-xs" placeholder="Cari nama atau hostname…" value={q} onChange={(e) => setQ(e.target.value)} />
        <NativeSelect
          className="w-auto"
          aria-label="Filter konektivitas"
          value={connectivity}
          onChange={(e) => router.replace(e.target.value ? `/servers?connectivity=${e.target.value}` : "/servers")}
        >
          <option value="">Semua konektivitas</option>
          <option value="OK">Terhubung</option>
          <option value="FAILED">Gagal</option>
          <option value="HOST_KEY_MISMATCH">Host key berubah</option>
          <option value="UNKNOWN">Belum dites</option>
        </NativeSelect>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.items.length ? (
        <EmptyState title="Belum ada server">
          {can("asset:manage") ? "Tambahkan server pertama untuk mulai." : "Tidak ada server yang cocok."}
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nama</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>OS</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>SSH</TableHead>
                <TableHead>Kritikalitas</TableHead>
                <TableHead className="text-right">Website</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((s) => (
                <TableRow key={s.id} className="cursor-pointer" onClick={() => router.push(`/servers/${s.id}`)}>
                  <TableCell className="font-medium">
                    <Link href={`/servers/${s.id}`} onClick={(e) => e.stopPropagation()} className="hover:underline">
                      {s.name}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {s.hostname}:{s.ssh_port}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {s.os_name ? `${s.os_name} ${s.os_version ?? ""}` : "—"}
                  </TableCell>
                  <TableCell><StatusBadge status={s.status} /></TableCell>
                  <TableCell><ConnectivityBadge status={s.connectivity_status} /></TableCell>
                  <TableCell><CriticalityText value={s.criticality} /></TableCell>
                  <TableCell className="text-right tabular-nums">{s.website_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {creating && <ServerFormDialog open={creating} onOpenChange={setCreating} />}
    </>
  );
}

export default function ServersPage() {
  return (
    <Suspense>
      <ServersContent />
    </Suspense>
  );
}
