"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { ApiError } from "@/lib/api/client";
import { AIPass } from "@/lib/api/endpoints";
import { useAuth } from "@/lib/auth/store";
import { useT } from "@/lib/i18n/provider";
import { qk } from "@/lib/query/keys";

export function AIPassConnectionCard() {
  const t = useT();
  const { token } = useAuth();
  const qc = useQueryClient();
  const handledCallback = useRef(false);

  useEffect(() => {
    if (handledCallback.current) return;
    handledCallback.current = true;
    const url = new URL(window.location.href);
    const result = url.searchParams.get("aipass");
    if (result === "connected") toast.success(t("aipass.connectedNow"));
    if (result === "error") toast.error(t("aipass.callbackError"));
    if (result) {
      url.searchParams.delete("aipass");
      window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
    }
  }, [t]);

  const statusQ = useQuery({
    queryKey: qk.aipassStatus,
    queryFn: () => AIPass.status(token ?? undefined),
  });
  const connected = statusQ.data?.connected ?? false;
  const needsReconnect = statusQ.data?.status === "reauth_required";
  const modelsQ = useQuery({
    queryKey: qk.aipassModels,
    queryFn: () => AIPass.models(token ?? undefined),
    enabled: connected && !needsReconnect,
  });

  const invalidate = async () => {
    await Promise.all([
      qc.invalidateQueries({ queryKey: qk.aipassStatus }),
      qc.invalidateQueries({ queryKey: qk.aipassModels }),
      qc.invalidateQueries({ queryKey: qk.llmCredentials }),
    ]);
  };
  const mutationError = (error: Error) => {
    toast.error(error instanceof ApiError ? error.message : t("aipass.error"));
  };

  const chooseModel = useMutation({
    mutationFn: (model: string) => AIPass.selectModel(model, token ?? undefined),
    onSuccess: () => {
      toast.success(t("aipass.modelSaved"));
      void invalidate();
    },
    onError: mutationError,
  });
  const setActive = useMutation({
    mutationFn: (active: boolean) => AIPass.setActive(active, token ?? undefined),
    onSuccess: () => void invalidate(),
    onError: mutationError,
  });
  const disconnect = useMutation({
    mutationFn: () => AIPass.disconnect(token ?? undefined),
    onSuccess: () => {
      toast.success(t("aipass.disconnected"));
      void invalidate();
    },
    onError: mutationError,
  });

  if (statusQ.isSuccess && !statusQ.data.available) {
    return (
      <Card className="grid gap-2 p-6">
        <h2 className="font-semibold">{t("aipass.title")}</h2>
        <p className="text-muted-foreground text-sm">{t("aipass.unavailable")}</p>
      </Card>
    );
  }

  return (
    <Card className="grid gap-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid gap-1">
          <div className="flex items-center gap-2">
            <h2 className="font-semibold">{t("aipass.title")}</h2>
            {connected && (
              <Badge variant="secondary">
                {statusQ.data?.status === "reauth_required"
                  ? t("aipass.reconnect")
                  : t("aipass.connected")}
              </Badge>
            )}
          </div>
          <p className="text-muted-foreground text-sm">{t("aipass.description")}</p>
        </div>

        <div className="flex items-center gap-2">
          {(!connected || needsReconnect) && (
            <form action="/api/v1/me/aipass/connect" method="post">
              <Button type="submit" disabled={statusQ.isPending}>
                {needsReconnect ? t("aipass.reconnectAction") : t("aipass.connect")}
              </Button>
            </form>
          )}
          {connected && needsReconnect && (
            <Button
              type="button"
              variant="ghost"
              disabled={disconnect.isPending}
              onClick={() => disconnect.mutate()}
            >
              {t("aipass.disconnect")}
            </Button>
          )}
        </div>
      </div>

      {connected && !needsReconnect && (
        <>
          <label className="grid gap-1.5 text-sm">
            <span className="font-medium">{t("aipass.model")}</span>
            <select
              aria-label={t("aipass.model")}
              className="border-border bg-background h-9 rounded-md border px-3 text-sm"
              value={statusQ.data?.model ?? ""}
              disabled={modelsQ.isPending || chooseModel.isPending}
              onChange={(event) => chooseModel.mutate(event.target.value)}
            >
              <option value="" disabled>
                {modelsQ.isPending ? t("aipass.modelsLoading") : t("aipass.modelChoose")}
              </option>
              {(modelsQ.data?.models ?? []).map((model) => (
                <option key={model.id} value={model.id}>
                  {model.name}
                </option>
              ))}
            </select>
            <span className="text-muted-foreground text-xs">{t("aipass.modelsLive")}</span>
          </label>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <Switch
                aria-label={t("aipass.active")}
                checked={statusQ.data?.active ?? false}
                disabled={!statusQ.data?.model || setActive.isPending}
                onCheckedChange={(active) => setActive.mutate(active)}
              />
              {t("aipass.active")}
            </label>
            <Button
              type="button"
              variant="ghost"
              disabled={disconnect.isPending}
              onClick={() => disconnect.mutate()}
            >
              {t("aipass.disconnect")}
            </Button>
          </div>
        </>
      )}
    </Card>
  );
}
