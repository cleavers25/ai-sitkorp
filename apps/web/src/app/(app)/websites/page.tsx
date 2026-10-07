"use client";

import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { EmptyState, PageHeader } from "@/components/page-header";
import { CriticalityText, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { WebsiteFormDialog } from "@/components/website-form-dialog";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import type { Page, Website } from "@/lib/types";

export default function WebsitesPage() {
  const router = useRouter();
  const { can } = useMe();
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["websites", q],
    queryFn: () => api<Page<Website>>(`/websites?limit=500${q ? `&q=${encodeURIComponent(q)}` : ""}`),
  });

  return (
    <>
      <PageHeader
        title="Website"
        description="Website yang dipantau dan server tempatnya berjalan."
        actions={
          can("asset:manage") && (
            <Button onClick={() => setCreating(true)}>
              <Plus /> Tambah website
            </Button>
          )
        }
      />

      <Input className="mb-4 max-w-xs" placeholder="Cari nama atau domain…" value={q} onChange={(e) => setQ(e.target.value)} />

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.items.length ? (
        <EmptyState title="Belum ada website">
          {can("asset:manage") ? "Tambahkan website lalu hubungkan ke server-nya." : "Tidak ada website yang cocok."}
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Website</TableHead>
                <TableHead>Server</TableHead>
                <TableHead>Aplikasi</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Kritikalitas</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((w) => (
                <TableRow key={w.id} className="cursor-pointer" onClick={() => router.push(`/websites/${w.id}`)}>
                  <TableCell>
                    <Link href={`/websites/${w.id}`} onClick={(e) => e.stopPropagation()} className="font-medium hover:underline">
                      {w.name}
                    </Link>
                    <p className="truncate text-xs text-muted-foreground">{w.url}</p>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{w.server?.name ?? "—"}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {[w.application, w.web_server, w.runtime].filter(Boolean).join(" · ") || "—"}
                  </TableCell>
                  <TableCell><StatusBadge status={w.status} /></TableCell>
                  <TableCell><CriticalityText value={w.criticality} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {creating && <WebsiteFormDialog open={creating} onOpenChange={setCreating} />}
    </>
  );
}
