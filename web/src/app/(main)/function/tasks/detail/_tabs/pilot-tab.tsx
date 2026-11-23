"use client";

import * as React from "react";

import Link from "next/link";

import { AlertCircleIcon, CheckCircle2Icon, ClockIcon, RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";

import type { TaskPilotState } from "./pilot-controls";

const phaseMessage: Record<string, string> = {
  aprobado: "Alcance aprobado",
  bloqueado: "Sin autorización activa",
  listo: "Herramientas disponibles",
  pendiente: "Preparación pendiente",
  ejecutado_parcial: "Actividad registrada, cobertura no verificada",
  no_ejecutado: "Sin ejecución registrada",
  hallazgos_confirmados: "Hallazgos confirmados registrados",
  requiere_revision: "Revisión técnica pendiente",
  sin_evidencia: "Sin evidencia suficiente",
  requiere_autorizacion_especifica: "Requiere autorización independiente",
  no_demostrada: "Acceso o impacto sin demostrar",
  sin_cierre_verificado: "Cierre completo aún no verificado",
};
function fmtDate(value?: string | null) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("es-PY");
}
function num(v?: number) {
  return (v ?? 0).toLocaleString("es-PY");
}
export function PilotTab({
  taskId,
  pilot,
  onNavigate,
}: {
  taskId: string;
  pilot: TaskPilotState;
  onNavigate: (tab: string) => void;
}) {
  const { status, loading, error, refresh } = pilot;
  const [working, setWorking] = React.useState(false);
  const [ticket, setTicket] = React.useState("");
  const [domain, setDomain] = React.useState("");
  const [expiryHours, setExpiryHours] = React.useState("24");
  const [interval, setInterval] = React.useState("60");
  const [labResult, setLabResult] = React.useState<import("@/lib/nandutest-pilot").PilotLabResult | null>(null);

  React.useEffect(() => {
    const domains = status?.scoped_domains ?? [];
    const approvedDomain = status?.approval?.domain ?? "";
    setDomain((previous) => {
      if (domains.includes(previous)) return previous;
      if (domains.includes(approvedDomain)) return approvedDomain;
      return domains[0] ?? "";
    });
  }, [status]);

  const authorize = async () => {
    if (!domain || !ticket.trim() || ticket.trim().length < 8) {
      toast.error("Indicá un objetivo autorizado y una referencia de aprobación de al menos 8 caracteres");
      return;
    }
    const hrs = Number(expiryHours);
    const mins = Number(interval);
    if (!Number.isFinite(hrs) || hrs < 1 || hrs > 168 || !Number.isInteger(mins) || mins < 60 || mins > 1440) {
      toast.error("Vencimiento o intervalo fuera de los límites");
      return;
    }
    setWorking(true);
    try {
      await api.authorizeTaskPilot(taskId, {
        domain,
        ticket: ticket.trim(),
        mode: "passive_https",
        expires_at: new Date(Date.now() + hrs * 3600 * 1000).toISOString(),
        interval_minutes: mins,
      });
      toast.success("Piloto automático activado. Consultá la próxima comprobación en su estado.");
      await refresh();
    } catch (err) {
      toast.error("Autorización rechazada: " + String(err));
    } finally {
      setWorking(false);
    }
  };
  const runLab = async () => {
    setWorking(true);
    try {
      const result = await api.runTaskPilotLab(taskId);
      setLabResult(result);
      if (result.ok && result.phases_passed === 8) {
        toast.success("Ocho fases del laboratorio completadas; acceso al canario sintético verificado");
      }
      await refresh();
    } catch (err) {
      toast.error("El laboratorio no pudo completar sus comprobaciones: " + String(err));
    } finally {
      setWorking(false);
    }
  };
  const revoke = async () => {
    setWorking(true);
    try {
      await api.revokeTaskPilot(taskId);
      toast.success("Piloto automático detenido. El historial se conserva.");
      await refresh();
    } catch (err) {
      toast.error(String(err));
    } finally {
      setWorking(false);
    }
  };
  const runCheck = async () => {
    setWorking(true);
    try {
      const result = await api.checkTaskPilot(taskId);
      toast.info(result.outcome === "ok" ? "Comprobación HTTPS finalizada" : "Resultado: " + result.outcome);
      await refresh();
    } catch (err) {
      toast.error("Comprobación no ejecutada: " + String(err));
    } finally {
      setWorking(false);
    }
  };
  const m = status?.metrics;
  const approved = Boolean(
    status?.pilot_enabled && status.approval && Date.parse(status.approval.expires_at) > Date.now() && !error,
  );
  const canAuthorize = Boolean(status && !loading && !error && status.automation_enabled !== false);
  const phases = status?.phases ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>{approved ? "Gestionar piloto automático" : "Activar piloto automático"}</CardTitle>
          <p className="text-sm text-muted-foreground">
            Elegí el dominio, la frecuencia y el vencimiento, y registrá la referencia de autorización. El piloto
            seguirá comprobando esta revisión aunque cierres la página.
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-muted-foreground">
              El dominio debe estar en el alcance y tener permiso explícito.
            </span>
            <Button type="button" variant="link" size="sm" onClick={() => onNavigate("overview")}>
              Configurar alcance
            </Button>
            <Button type="button" variant="link" size="sm" onClick={() => onNavigate("intercept")}>
              Revisar permisos
            </Button>
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              No se pudo verificar el estado: {error}
            </p>
          )}
          {status?.automation_enabled === false && (
            <p role="alert" className="text-sm text-destructive">
              El servicio tiene deshabilitada la programación del piloto.
            </p>
          )}
          {status && status.scoped_domains.length === 0 && (
            <p role="status" className="text-sm text-amber-700 dark:text-amber-400">
              Primero agregá el dominio de esta revisión en Configurar alcance. Luego volvé a esta pestaña.
            </p>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            <label className="space-y-1 text-sm">
              <span>Dominio exacto aprobado</span>
              <select
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full rounded-md border bg-background p-2"
                disabled={working || !canAuthorize}
              >
                {!domain && <option value="">Seleccioná un dominio del alcance</option>}
                {(status?.scoped_domains ?? []).map((host) => (
                  <option key={host} value={host}>
                    {host}
                  </option>
                ))}
              </select>
            </label>
            <label htmlFor="pilot-approval-ticket" className="space-y-1 text-sm">
              <span>Ticket o referencia de autorización</span>
              <Input
                id="pilot-approval-ticket"
                value={ticket}
                onChange={(e) => setTicket(e.target.value)}
                placeholder="Ej. CHG-2026-00123"
                disabled={working || !canAuthorize}
              />
            </label>
            <label className="space-y-1 text-sm">
              <span>Vencimiento</span>
              <select
                value={expiryHours}
                onChange={(e) => setExpiryHours(e.target.value)}
                className="w-full rounded-md border bg-background p-2"
                disabled={working || !canAuthorize}
              >
                <option value="24">24 horas</option>
                <option value="72">3 días</option>
                <option value="168">7 días</option>
              </select>
            </label>
            <label className="space-y-1 text-sm">
              <span>Intervalo entre verificaciones</span>
              <select
                value={interval}
                onChange={(e) => setInterval(e.target.value)}
                className="w-full rounded-md border bg-background p-2"
                disabled={working || !canAuthorize}
              >
                <option value="60">Cada hora</option>
                <option value="360">Cada 6 horas</option>
                <option value="720">Cada 12 horas</option>
                <option value="1440">Cada 24 horas</option>
              </select>
            </label>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => void authorize()}
              disabled={working || !canAuthorize || !domain || ticket.trim().length < 8}
            >
              <ShieldCheckIcon className="mr-2 h-4 w-4" />
              {approved ? "Renovar autorización" : "Activar piloto automático"}
            </Button>
            <Button variant="outline" disabled={working || !approved} onClick={() => void runCheck()}>
              Verificar ahora
            </Button>
            <Button
              variant="destructive"
              disabled={working || !status?.approval?.enabled}
              onClick={() => void revoke()}
            >
              Detener piloto
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Las comprobaciones comienzan automáticamente según la frecuencia y disponibilidad del servicio. El estado
            muestra la próxima ejecución y el vencimiento de la autorización.
          </p>
          <p className="flex items-start gap-2 text-xs text-muted-foreground">
            <AlertCircleIcon className="mt-0.5 h-4 w-4 shrink-0" />
            Lograr acceso solo puede acreditarse mediante una prueba específica con cuentas de ensayo y autorización
            expresa. No se prueba ni se declara automáticamente en este piloto.
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="space-y-2 pt-5 text-sm">
          <p>
            El piloto incluye controles de DNS, certificado, cabeceras y cookies, espera progresiva ante fallos y
            revisión de observaciones repetidas.
          </p>
          <Link href="/system/autopilot" className="text-primary underline underline-offset-4">
            Ver evidencia, comparación y aprendizaje del autopiloto
          </Link>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheckIcon className="h-5 w-5" /> Estado del piloto automático
              </CardTitle>
              <p className="mt-2 text-sm text-muted-foreground">
                Auditoría pasiva periódica, con autorización administrativa por objetivo y vencimiento. No ejecuta
                explotación, intentos de acceso ni movimientos laterales automáticamente.
              </p>
            </div>
            <Button variant="outline" size="sm" disabled={loading || working} onClick={() => void refresh()}>
              <RefreshCwIcon className="mr-2 h-4 w-4" />
              Actualizar
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading && !status ? <p className="text-sm text-muted-foreground">Cargando evidencias...</p> : null}
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span
              className={
                "inline-flex items-center gap-2 rounded-full border px-3 py-1 font-medium " +
                (approved ? "text-emerald-700 dark:text-emerald-400" : "text-amber-700 dark:text-amber-400")
              }
            >
              {approved ? <CheckCircle2Icon className="h-4 w-4" /> : <ClockIcon className="h-4 w-4" />}
              {approved ? "Piloto automático activo" : "Piloto sin ejecución automática habilitada"}
            </span>
            <span className="text-muted-foreground">Controles pasivos de DNS, TLS, cabeceras y cookies</span>
          </div>
          {status?.scope_error ? (
            <p role="alert" className="text-sm text-destructive">
              Bloqueo de alcance: {status.scope_error}
            </p>
          ) : null}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {(
              [
                ["Llamadas de herramientas", num(m?.tool_results)],
                ["Errores de herramientas", num(m?.tool_errors)],
                ["Hallazgos / confirmados", num(m?.findings) + " / " + num(m?.confirmed_findings)],
                ["Memorias aprobadas", num(m?.human_reviewed_memory)],
              ] as const
            ).map(([label, value]) => (
              <div key={label} className="rounded-lg border p-3">
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="mt-1 text-xl font-semibold tabular-nums">{value}</p>
              </div>
            ))}
          </div>
          <div className="rounded-lg border p-3 text-sm">
            <p className="font-medium">Resultado verificable de comprobaciones pasivas</p>
            <p className="mt-1 text-muted-foreground">
              {num(m?.passive_ok_30d)} correctas de {num(m?.passive_checks_30d)} intentos en los últimos 30 días
            </p>
            <p className="mt-1 text-muted-foreground">
              Cambios de estado HTTP detectados: {num(m?.status_changes_30d)}
            </p>
            <p className="mt-1 text-muted-foreground">
              Motor local Qwen: {num(m?.local_llm_ok)} correctas / {num(m?.local_llm_error)} fallidas. Respaldo externo:{" "}
              {num(m?.external_llm_ok)} correctas / {num(m?.external_llm_error)} fallidas.
            </p>
            <p className="mt-1 text-muted-foreground">
              Última: {fmtDate(status?.approval?.last_check)} · HTTP {status?.approval?.last_http ?? "—"}
              {" · "}
              {status?.approval?.last_latency_ms ?? "—"} ms
            </p>
            <p className="mt-1 text-muted-foreground">
              Próxima comprobación: {fmtDate(status?.approval?.next_check)}
              {" · "}Vence: {fmtDate(status?.approval?.expires_at)}
            </p>
          </div>
          {(status?.history?.length ?? 0) > 0 ? (
            <div className="space-y-2">
              <p className="text-sm font-medium">Últimas comprobaciones registradas</p>
              {status?.history?.slice(0, 6).map((item, index) => (
                <div
                  key={item.checked_at + index}
                  className="flex flex-wrap justify-between gap-2 rounded border p-2 text-xs"
                >
                  <span>{fmtDate(item.checked_at)}</span>
                  <span>
                    HTTP {item.http_status || "—"} · {item.latency_ms} ms · {item.outcome}
                  </span>
                  {item.status_changed ? <span className="text-amber-700">Cambio detectado</span> : null}
                </div>
              ))}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Fases y evidencia del pentest</CardTitle>
          <p className="text-sm text-muted-foreground">
            Una fase solo figura como confirmada si existe evidencia. Las actividades registradas no demuestran por sí
            mismas acceso ni cobertura completa.
          </p>
        </CardHeader>
        <CardContent className="grid gap-2 md:grid-cols-2">
          {phases.map((phase, index) => (
            <div key={phase.id} className="flex items-start gap-3 rounded-lg border p-3">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">
                {index + 1}
              </span>
              <div className="min-w-0">
                <p className="text-sm font-medium">{phase.label}</p>
                <p className="text-xs text-muted-foreground">{phaseMessage[phase.state] ?? phase.state}</p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Prueba integral de ocho fases · laboratorio aislado</CardTitle>
          <p className="text-sm text-muted-foreground">
            Ejecuta un ensayo real sobre un servidor efímero 127.0.0.1, con controles de denegación y acceso mediante
            credencial de laboratorio. No examina objetivos externos ni intenta obtener acceso a sistemas empresariales.
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button disabled={working} variant="outline" onClick={() => void runLab()}>
            <ShieldCheckIcon className="mr-2 h-4 w-4" /> Probar las ocho fases en laboratorio
          </Button>
          {status?.lab && (
            <p className="text-sm">
              Última prueba: {fmtDate(status.lab.checked_at)} · {status.lab.phases_passed}/8 fases ·{" "}
              {status.lab.duration_ms} ms. Acceso real demostrado: no.
            </p>
          )}
          {labResult && (
            <div className="grid gap-2 md:grid-cols-2">
              {labResult.phases.map((phase) => (
                <div key={phase.id} className="rounded border p-2 text-xs">
                  <p className="font-medium">
                    {phase.id} · {phase.state}
                  </p>
                  <p className="text-muted-foreground">{phase.evidence}</p>
                </div>
              ))}
              <p className="col-span-full text-xs text-muted-foreground">
                Prueba sintética verificable: {labResult.canary_sha256.slice(0, 16)}…{" · "}No certifica una intrusión
                en producción.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
