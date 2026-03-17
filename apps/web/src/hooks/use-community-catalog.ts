import type { SkillhubCatalogData } from "@/types/desktop";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

const CATALOG_QUERY_KEY = ["skillhub", "catalog"] as const;
const DETAIL_QUERY_KEY = ["skillhub", "detail"] as const;

export function useCommunitySkills() {
  return useQuery({
    queryKey: CATALOG_QUERY_KEY,
    queryFn: async (): Promise<SkillhubCatalogData> => {
      const res = await fetch("/api/v1/skillhub/catalog");
      if (!res.ok) throw new Error(`Catalog fetch failed: ${res.status}`);
      return res.json();
    },
    staleTime: 5 * 60 * 1000,
  });
}

export function useInstallSkill() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (slug: string) => {
      const res = await fetch("/api/v1/skillhub/install", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug }),
      });
      if (!res.ok) throw new Error(`Install request failed: ${res.status}`);
      const result = (await res.json()) as { ok: boolean; error?: string };
      if (!result.ok) {
        throw new Error(result.error ?? "Install failed");
      }
      return result;
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: CATALOG_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: DETAIL_QUERY_KEY });
    },
  });
}

export function useUninstallSkill() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (slug: string) => {
      const res = await fetch("/api/v1/skillhub/uninstall", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug }),
      });
      if (!res.ok) throw new Error(`Uninstall request failed: ${res.status}`);
      const result = (await res.json()) as { ok: boolean; error?: string };
      if (!result.ok) {
        throw new Error(result.error ?? "Uninstall failed");
      }
      return result;
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: CATALOG_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: DETAIL_QUERY_KEY });
    },
  });
}

export function useRefreshCatalog() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      return { ok: true, skillCount: 0 };
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: CATALOG_QUERY_KEY });
    },
  });
}
