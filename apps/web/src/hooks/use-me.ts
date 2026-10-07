"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Me, Permission } from "@/lib/types";

export function useMe() {
  const query = useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/auth/me"), staleTime: 60_000 });
  const can = (p: Permission) => query.data?.permissions.includes(p) ?? false;
  return { ...query, me: query.data, can };
}
