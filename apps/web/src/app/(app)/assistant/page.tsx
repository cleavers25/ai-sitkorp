"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MessageSquarePlus, Trash2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { ChatPanel } from "@/components/chat-panel";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AIConversation } from "@/lib/types";
import { cn } from "@/lib/utils";

function AssistantContent() {
  const router = useRouter();
  const params = useSearchParams();
  const qc = useQueryClient();
  const current = params.get("c");

  const convs = useQuery({
    queryKey: ["ai-conversations", "global"],
    queryFn: () => api<AIConversation[]>("/ai/conversations?scope=global"),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/ai/conversations/${id}`, { method: "DELETE" }),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["ai-conversations"] });
      if (id === current) router.replace("/assistant");
    },
  });
  const open = (id: string | null) => router.replace(id ? `/assistant?c=${id}` : "/assistant");

  return (
    <div className="-my-2 grid h-[calc(100dvh-4rem)] gap-4 md:h-[calc(100dvh-4rem)] md:grid-cols-[15rem_1fr]">
      <aside className="hidden min-h-0 flex-col rounded-xl border bg-card p-2 md:flex">
        <Button variant="outline" size="sm" className="mb-2 justify-start" onClick={() => open(null)}>
          <MessageSquarePlus /> Percakapan baru
        </Button>
        <div className="min-h-0 flex-1 space-y-0.5 overflow-y-auto">
          {convs.data?.map((c) => (
            <div key={c.id} className={cn("group flex items-center rounded-md hover:bg-muted", c.id === current && "bg-muted")}>
              <button className="min-w-0 flex-1 px-2 py-1.5 text-left" onClick={() => open(c.id)}>
                <p className="truncate text-sm">{c.title}</p>
                <p className="text-[11px] text-muted-foreground">{formatDateTime(c.updated_at)}</p>
              </button>
              <Button variant="ghost" size="icon-xs" className="mr-1 opacity-0 group-hover:opacity-100"
                aria-label="Hapus percakapan" onClick={() => remove.mutate(c.id)}>
                <Trash2 />
              </Button>
            </div>
          ))}
          {convs.data?.length === 0 && <p className="px-2 py-4 text-xs text-muted-foreground">Belum ada percakapan.</p>}
        </div>
      </aside>

      <section className="flex min-h-0 flex-col">
        <div className="mb-3">
          <h1 className="text-xl font-semibold tracking-tight">AI Assistant</h1>
          <p className="text-sm text-muted-foreground">
            Tanya kondisi semua server dan website terdaftar. Percakapan di sini hanya terlihat oleh Anda.
          </p>
        </div>
        <ChatPanel
          key={current ?? "new"}
          conversationId={current}
          onConversationCreated={(id) => open(id)}
          className="min-h-0 flex-1"
        />
      </section>
    </div>
  );
}

export default function AssistantPage() {
  return (
    <Suspense>
      <AssistantContent />
    </Suspense>
  );
}
