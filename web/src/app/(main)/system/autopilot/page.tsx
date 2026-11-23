"use client";

import * as React from "react";

import Link from "next/link";

import { Download, RefreshCw, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { type AuditStatus, auditAPI, auditPlanState } from "@/lib/autopilot";

const runLabels: Record<string, string> = {
  running: "En ejecución",
  completed: "Completada",
  blocked: "Detenida por alcance",
  unavailable: "No disponible",
  canceled: "Cancelada",
  interrupted: "Interrumpida",
};
const checkLabels = { pass: "Control observado", warning: "Revisar", not_evaluated: "No evaluado" };
const date = (value: string) => new Date(value).toLocaleString("es-PY");
const selectClass = "h-9 rounded-md border bg-background px-3 text-sm";

export default function AutopilotPage() {
  const [data, setData] = React.useState<AuditStatus | null>(null);
  const [selected, setSelected] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const reload = React.useCallback(async () => {
    try {
      setData(await auditAPI.status(selected));
      setError("");
    } catch (caught) {
      setError(String(caught));
    }
  }, [selected]);
  React.useEffect(() => {
    void reload();
    const timer = setInterval(() => void reload(), 10000);
    return () => clearInterval(timer);
  }, [reload]);

  async function action(work: () => Promise<unknown>, message: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await work();
      setNotice(message);
      await reload();
    } catch (caught) {
      setError(String(caught));
    } finally {
      setBusy(false);
    }
  }
  async function download(id: number) {
    await action(async () => {
      const evidence = await auditAPI.evidence(id);
      const blob = new Blob([evidence.evidence_json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `nandutest-auditoria-${id}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    }, "Evidencia descargada; su SHA-256 figura en la ejecución.");
  }

  return (
    <div className="flex flex-1 flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <ShieldCheck className="size-5" /> Autopiloto de auditoría
          </h1>
          <p className="text-muted-foreground text-sm">
            Controles continuos de DNS, HTTPS, cabeceras y cookies, con evidencia y revisión.
          </p>
        </div>
        <Button variant="outline" size="sm" disabled={busy} onClick={() => void reload()}>
          <RefreshCw className="size-4" /> Actualizar
        </Button>
      </div>
      <div aria-live="polite" className="space-y-2 text-sm">
        {error && (
          <p className="text-destructive" role="alert">
            {error}
          </p>
        )}
        {notice && <p>{notice}</p>}
        {data && !data.enabled && (
          <p className="text-destructive">
            El autopiloto está deshabilitado por configuración. Los planes se conservan sin ejecutar solicitudes.
          </p>
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Ejecuciones completas", `${data?.metrics.completed ?? 0} / ${data?.metrics.runs ?? 0}`],
          ["Intentos HTTPS", String(data?.metrics.requests ?? 0)],
          [
            "Confirmadas / revisadas",
            `${data?.metrics.confirmed ?? 0} / ${(data?.metrics.confirmed ?? 0) + (data?.metrics.discarded ?? 0)}`,
          ],
          ["Tokens LLM por control", "0"],
        ].map(([label, value]) => (
          <Card key={label}>
            <CardContent className="pt-5">
              <p className="text-muted-foreground text-xs">{label}</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <p className="text-muted-foreground text-xs">
        Métricas del historial retenido y del filtro seleccionado. Las revisiones cuentan reglas por origen; no
        representan la precisión global de un pentest.
      </p>
      <Card>
        <CardHeader>
          <CardTitle>Una autorización por tarea</CardTitle>
          <CardDescription>
            El alcance, el ticket y el vencimiento se administran en Piloto continuo de cada tarea. Estos controles
            amplían el análisis de su misma petición HEAD, sin agregar tráfico ni reactivar tareas.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            Dominio exacto y regla de permiso obligatorios. Frecuencia mínima de una hora, autorización hasta siete
            días, una ejecución global a la vez y máximo siete segundos de red.
          </p>
          <Link href="/function/tasks" className="text-primary underline underline-offset-4">
            Ir a tareas para autorizar el piloto
          </Link>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Planes y alcance</CardTitle>
          <CardDescription>
            La autorización vence automáticamente. Ante cinco fallos consecutivos, el plan se pausa. Verificar ahora
            respeta la misma frecuencia mínima de una hora.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 lg:grid-cols-2">
          {(data?.plans ?? []).map((plan) => {
            const state = auditPlanState(plan);
            const valid = new Date(plan.authorized_until).getTime() > Date.now();
            return (
              <div key={plan.id} className="space-y-3 rounded-lg border p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="font-medium">{plan.name}</h3>
                  <Badge variant={plan.enabled && valid ? "default" : "outline"}>{state}</Badge>
                </div>
                <p className="break-all text-sm">{plan.target}</p>
                <div className="text-muted-foreground space-y-1 text-xs">
                  <p>
                    Autorización: {plan.authorization_ref} · vence {date(plan.authorized_until)}
                  </p>
                  <p>
                    Cada {plan.interval_seconds / 3600} h · fallos consecutivos: {plan.failure_streak}
                  </p>
                  {valid && plan.enabled && <p>Próxima: {date(plan.next_run_at)}</p>}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {valid && plan.enabled && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy || !data?.enabled}
                      onClick={() =>
                        void action(
                          () => auditAPI.run(plan.id),
                          "Comprobación terminada. Revisá su estado y evidencia en el historial.",
                        )
                      }
                    >
                      Verificar ahora
                    </Button>
                  )}
                  {plan.enabled && (
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy}
                      onClick={() =>
                        void action(() => auditAPI.revoke(plan.id), "Autorización revocada. El historial se conserva.")
                      }
                    >
                      Revocar
                    </Button>
                  )}
                  <Link
                    href={`/function/tasks/detail?id=${plan.id}&tab=pilot`}
                    className="text-primary text-sm underline underline-offset-4"
                  >
                    Configurar en la tarea
                  </Link>
                </div>
              </div>
            );
          })}
          {data?.plans.length === 0 && (
            <p className="text-muted-foreground text-sm">
              Todavía no hay autorizaciones del piloto. Registrá el alcance y el permiso desde una tarea para iniciar el
              ciclo.
            </p>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle>Evidencia y aprendizaje</CardTitle>
            <label className="flex items-center gap-2 text-sm" htmlFor="audit-filter">
              <span>Plan</span>
              <select
                id="audit-filter"
                className={`${selectClass} max-w-64`}
                value={selected}
                onChange={(event) => setSelected(event.target.value)}
              >
                <option value="">Todos</option>
                {data?.plans.map((plan) => (
                  <option value={plan.id} key={plan.id}>
                    {plan.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <CardDescription>{data?.learning ?? "Cargando historial..."}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {(data?.runs ?? []).map((run) => (
            <details key={run.id} className="rounded-lg border p-3">
              <summary className="cursor-pointer space-y-1 text-sm">
                <span className="font-medium">
                  #{run.id} · {data?.plans.find((plan) => plan.id === run.plan_id)?.name ?? `Plan ${run.plan_id}`} ·{" "}
                  {runLabels[run.status] ?? run.status}
                </span>
                <span className="text-muted-foreground ml-2 text-xs">{date(run.started_at)}</span>
              </summary>
              <div className="mt-3 space-y-3">
                <p className="text-muted-foreground text-xs">
                  {run.report.requests ?? 0} solicitudes · {run.report.duration_ms ?? 0} ms ·{" "}
                  {run.report.compared
                    ? `${run.report.new} nuevas, ${run.report.recurring} repetidas, ${run.report.resolved} resueltas respecto a la última ejecución completa`
                    : "Sin comparación válida con una ejecución anterior"}
                </p>
                {(run.report.observations ?? []).map((observation) => (
                  <div key={observation.fingerprint} className="space-y-2 rounded-md bg-muted/40 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <strong className="text-sm">{observation.title}</strong>
                      <Badge variant="outline">{checkLabels[observation.status]}</Badge>
                      {observation.verdict && <Badge variant="secondary">Revisión: {observation.verdict}</Badge>}
                    </div>
                    <p className="text-muted-foreground text-xs">{observation.evidence}</p>
                    {run.status === "completed" && observation.status === "warning" && (
                      <div className="flex flex-wrap gap-2">
                        {[
                          ["confirmado", "Confirmar"],
                          ["descartado", "Falso positivo"],
                          ["desactualizado", "Reabrir revisión"],
                        ].map(([verdict, label]) => (
                          <Button
                            key={verdict}
                            size="sm"
                            variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void action(
                                () => auditAPI.review(run.id, observation.fingerprint, verdict),
                                "Revisión guardada para este origen y versión de regla.",
                              )
                            }
                          >
                            {label}
                          </Button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                {run.evidence_sha256 && (
                  <div className="space-y-2">
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void download(run.id)}>
                      <Download className="size-3" /> Descargar evidencia JSON
                    </Button>
                    <p className="text-muted-foreground break-all font-mono text-[10px]">
                      SHA-256: {run.evidence_sha256}
                    </p>
                  </div>
                )}
              </div>
            </details>
          ))}
          {data?.runs.length === 0 && (
            <p className="text-muted-foreground text-sm">Aún no hay ejecuciones para este filtro.</p>
          )}
          <p className="text-muted-foreground text-xs">
            Se muestran las últimas 20 ejecuciones; se conservan {data?.retention_per_plan ?? 200} por plan. Un control
            observado no equivale a un sitio seguro ni a una intrusión validada.
          </p>
          <Link href="/system/llm" className="text-primary text-sm underline underline-offset-4">
            Revisar la memoria Getangiru y el modelo activo
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
