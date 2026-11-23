"use client";

import * as React from "react";

import { ShieldCheckIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { PilotStatus } from "@/lib/nandutest-pilot";

// Share one status request between the review header and the pilot tab.
export function useTaskPilot(taskId: string, enabled: boolean) {
  const [status, setStatus] = React.useState<PilotStatus | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const generation = React.useRef(0);
  const currentTask = React.useRef(taskId);
  const refresh = React.useCallback(async () => {
    if (!enabled || !taskId || currentTask.current !== taskId) return;
    const request = ++generation.current;
    setLoading(true);
    try {
      const next = await api.getTaskPilot(taskId);
      if (request !== generation.current) return;
      setStatus(next);
      setError("");
    } catch (caught) {
      if (request === generation.current) setError(String(caught));
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, [taskId, enabled]);

  React.useEffect(() => {
    currentTask.current = enabled ? taskId : "";
    setStatus(null);
    setError("");
    setLoading(false);
    if (!enabled) return;
    void refresh();
    const refreshVisible = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    const timer = setInterval(refreshVisible, 30000);
    window.addEventListener("focus", refreshVisible);
    return () => {
      currentTask.current = "";
      generation.current++;
      clearInterval(timer);
      window.removeEventListener("focus", refreshVisible);
    };
  }, [taskId, enabled, refresh]);

  return { status: status?.task_id === Number(taskId) ? status : null, loading, error, refresh };
}

export type TaskPilotState = ReturnType<typeof useTaskPilot>;

export function PilotQuickControl({ pilot, onOpen }: { pilot: TaskPilotState; onOpen: () => void }) {
  const { status, loading, error } = pilot;
  const approval = status?.approval;
  const active = Boolean(status?.pilot_enabled && approval && Date.parse(approval.expires_at) > Date.now() && !error);
  let label = "Desactivado";
  let hint = "Activá las comprobaciones periódicas de esta revisión.";
  let action = "Activar piloto automático";
  if (active && approval) {
    label = "Activo";
    hint = `Próxima comprobación: ${new Date(approval.next_check).toLocaleString("es-PY")}`;
    action = "Gestionar piloto automático";
  } else if (status?.automation_enabled === false) {
    label = "Deshabilitado por configuración";
    hint = "La programación está detenida por la configuración del servicio.";
    action = "Ver piloto automático";
  } else if (status?.scope_error) {
    label = "Bloqueado por alcance";
    hint = "Revisá los permisos del dominio antes de activar el piloto.";
  } else if ((status?.approval?.failure_streak ?? 0) >= 5) {
    label = "Pausado por fallos";
    hint = "Revisá los resultados antes de renovar la autorización.";
  } else if (status?.approval && Date.parse(status.approval.expires_at) <= Date.now()) {
    label = "Autorización vencida";
    action = "Renovar piloto automático";
  }
  if (!status || error) {
    label = loading ? "Consultando estado" : "Estado sin verificar";
    hint = error
      ? "No se pudo actualizar el estado. Abrí el piloto para reintentar."
      : "Consultando la autorización de esta revisión.";
    action = "Ver piloto automático";
  }

  return (
    <section
      aria-label="Piloto automático"
      className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/30 p-3"
    >
      <div className="min-w-0 space-y-1">
        <p className="flex flex-wrap items-center gap-2 text-sm font-medium" aria-live="polite">
          <ShieldCheckIcon className="size-4 shrink-0" /> Piloto automático
          <span className={active ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>· {label}</span>
        </p>
        <p className="text-muted-foreground text-xs">{hint}</p>
      </div>
      <Button
        type="button"
        size="sm"
        variant={active ? "outline" : "default"}
        className="w-full sm:w-auto"
        onClick={onOpen}
      >
        <ShieldCheckIcon data-icon="inline-start" /> {action}
      </Button>
    </section>
  );
}
