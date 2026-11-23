"use client";

import * as React from "react";

import { BrainCircuit, Database, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { GetangiruRuntimeStatus, GetangiruSearchResult, GetangiruVerdict } from "@/lib/getangiru";

export function GetangiruIntegration() {
  const [status, setStatus] = React.useState<GetangiruRuntimeStatus | null>(null);
  const [query, setQuery] = React.useState("");
  const [searchResult, setSearchResult] = React.useState<GetangiruSearchResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [searching, setSearching] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [memoryTesting, setMemoryTesting] = React.useState(false);
  const [memoryTestResult, setMemoryTestResult] = React.useState<string | null>(null);
  const [reviewing, setReviewing] = React.useState("");
  const [modelResult, setModelResult] = React.useState<string | null>(null);
  const [routing, setRouting] = React.useState<Awaited<ReturnType<typeof api.nandutestLLMRouting>> | null>(null);
  const [routingBusy, setRoutingBusy] = React.useState(false);

  const refresh = React.useCallback(async () => {
    setLoading(true);
    try {
      const [runtime, routes] = await Promise.all([api.getangiruStatus(), api.nandutestLLMRouting()]);
      setStatus(runtime);
      setRouting(routes);
    } catch (error) {
      toast.error("No se pudo obtener el estado de Getangiru: " + String(error));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  async function changeRouting(mode: "qwen" | "openai" | "qwen_failover" | "openai_failover") {
    if (routingBusy || routing?.mode === mode) return;
    setRoutingBusy(true);
    try {
      await api.setNandutestLLMRouting(mode);
      await refresh();
      toast.success("Se aplicó la prioridad de modelos al motor de Ñandutest.");
    } catch (error) {
      toast.error("No se pudo cambiar el motor: " + String(error));
    } finally {
      setRoutingBusy(false);
    }
  }

  async function search() {
    if (!query.trim() || searching) return;
    setSearching(true);
    setSearchResult(null);
    try {
      setSearchResult(await api.getangiruSearch(query.trim()));
      await refresh();
    } catch (error) {
      toast.error("No fue posible recuperar memorias: " + String(error));
    } finally {
      setSearching(false);
    }
  }

  async function review(sourceId: string, verdict: GetangiruVerdict) {
    setReviewing(sourceId);
    try {
      await api.getangiruFeedback(sourceId, verdict);
      toast.success("Revisión guardada; la recuperación futura tendrá en cuenta el veredicto");
      await refresh();
      if (verdict !== "confirmado") {
        setSearchResult((previous) => {
          if (!previous) return previous;
          return { ...previous, items: previous.items.filter((item) => item.id !== sourceId) };
        });
      }
    } catch (error) {
      toast.error("No se pudo registrar la revisión: " + String(error));
    } finally {
      setReviewing("");
    }
  }

  async function testMemory() {
    if (memoryTesting) return;
    setMemoryTesting(true);
    setMemoryTestResult(null);
    try {
      const result = await api.getangiruConnectivityTest();
      setMemoryTestResult(
        "Conexión de memoria verificada. " +
          String(result.latency_ms ?? 0) +
          " ms; " +
          result.items.length +
          " coincidencias en consulta sintética.",
      );
      await refresh();
    } catch (error) {
      setMemoryTestResult("No se pudo verificar Getangiru: " + String(error));
    } finally {
      setMemoryTesting(false);
    }
  }

  async function testSharedModel() {
    if (testing) return;
    setTesting(true);
    setModelResult(null);
    try {
      const result = await api.getangiruSharedModelTest();
      setModelResult("Inferencia Qwen verificada desde Ñandutest: " + String(result.latency_ms) + " ms.");
      await refresh();
    } catch (error) {
      setModelResult("No se verificó la inferencia: " + String(error));
    } finally {
      setTesting(false);
    }
  }

  const memory = status?.memory;
  const model = status?.model;
  let memoryLabel = "Desconectada";
  if (memory?.connected) memoryLabel = "Conexión comprobada";
  else if (memory?.enabled) memoryLabel = "Configurada · sin probar";
  let modelLabel = "Sin inferencia verificada";
  if (model?.verified) modelLabel = "Probado · no seleccionado";
  if (model?.verified && model.active_for_nandutest) modelLabel = "Activo y probado";

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <BrainCircuit className="size-4" /> Getangiru · Memoria y modelo compartido
          </CardTitle>
          <CardDescription>
            Conexión entre plataformas, verificación independiente y aprendizaje por revisión humana.
          </CardDescription>
        </div>
        <Button variant="outline" size="sm" disabled={loading} onClick={() => void refresh()}>
          <RefreshCw className="size-4" /> {loading ? "Verificando..." : "Actualizar"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="rounded-lg border p-3" role="status" aria-live="polite">
          <p className="font-semibold">
            {memory?.connected && model?.verified
              ? "Integración privada funcionando: Getangiru y Qwen conectados"
              : memory?.connected
                ? "Memoria Getangiru conectada y funcionando"
                : "Verificación de la integración privada pendiente"}
          </p>
          <p className="mt-1 text-muted-foreground text-xs">
            {memory?.connected && model?.verified
              ? "Ñandutest recupera memoria autorizada desde Getangiru y puede ejecutar inferencias con Qwen local a través de Fly6PN."
              : memory?.connected
                ? "Ñandutest ya consulta Getangiru a través de Fly6PN. La inferencia de Qwen requiere una verificación independiente."
                : "Configuración detectada. Ejecutá la prueba de conexión para comprobar el servicio desde Ñandutest."}
          </p>
          <p className="mt-1 text-xs">
            {model?.verified && model.active_for_nandutest
              ? "Motor de IA principal: Qwen local seleccionado y verificado."
              : model?.verified
                ? "Qwen local: disponible y probado. El motor principal sigue siendo el perfil externo; las tareas generales todavía no se procesan con Qwen."
                : "No se ha confirmado que Qwen esté procesando las tareas generales de Ñandutest."}
          </p>
        </div>
        <div className="space-y-2 rounded-lg border p-3">
          <p className="font-semibold">Prioridad de modelos · Ñandutest</p>
          <p className="text-muted-foreground text-xs">
            Elegí un motor primario. El modo failover envía la solicitud a OpenAI solo cuando
            Qwen no responde o falla; nunca ejecuta ambos modelos en paralelo.
          </p>
          <div className="flex flex-wrap gap-2">
            {([
              ["qwen_failover", "Qwen primario · OpenAI respaldo"],
              ["qwen", "Solo Qwen local"],
              ["openai_failover", "OpenAI primario · Qwen respaldo"],
              ["openai", "Solo OpenAI"],
            ] as const).map(([mode, label]) => (
              <Button
                key={mode}
                size="sm"
                variant={routing?.mode === mode ? "default" : "outline"}
                disabled={routingBusy || !routing?.qwen_configured || !routing?.openai_profile}
                onClick={() => void changeRouting(mode)}
                aria-pressed={routing?.mode === mode}
              >
                {label}
              </Button>
            ))}
          </div>
          <p role="status" aria-live="polite" className="text-xs">
            {routingBusy
              ? "Validando conexión y aplicando el motor..."
              : routing?.mode === "qwen_failover"
                ? "ACTIVO: Qwen local es primario y OpenAI se utiliza como respaldo automático."
                : routing?.mode === "qwen"
                  ? "ACTIVO: solo Qwen local; sin respaldo externo."
                  : routing?.mode === "openai_failover"
                    ? "ACTIVO: OpenAI es primario y Qwen local es respaldo."
                    : routing?.mode === "openai"
                      ? "ACTIVO: solo OpenAI externo."
                      : "Verificando el orden real de los modelos..."}
          </p>
          <p className="text-muted-foreground text-xs">
            Las tareas con un modelo fijado explícitamente pueden conservar su selección.
            Qwen es un modelo pequeño y limitado; si una tarea supera su capacidad, el failover
            permite mantener el servicio, con posible consumo de la API de OpenAI.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Database className="size-4" />
              <span className="font-medium">Memoria Getangiru</span>
              <Badge variant={memory?.connected ? "default" : "outline"}>{memoryLabel}</Badge>
            </div>
            <p className="text-muted-foreground">{memory?.reason || "Consultando configuración..."}</p>
            <p className="text-muted-foreground text-xs">{memory?.scope || "Ámbito todavía no configurado"}</p>
            <p className="text-muted-foreground text-xs">
              Consultas: {memory?.metrics.requests ?? 0} · Caché: {memory?.metrics.cache_hits ?? 0} · Latencia p95:{" "}
              {memory?.metrics.p95_ms ?? 0} ms
            </p>
            <div className="space-y-1">
              <Button
                size="sm"
                variant="outline"
                onClick={() => void testMemory()}
                disabled={!memory?.enabled || memoryTesting}
              >
                <ShieldCheck className="size-4" />
                {memoryTesting ? "Verificando memoria (máx. 8 s)..." : "Probar conexión de memoria"}
              </Button>
              {memoryTestResult && (
                <p role="status" aria-live="polite" className="text-muted-foreground text-xs">
                  {memoryTestResult}
                </p>
              )}
            </div>
            <p className="text-muted-foreground text-xs">
              Revisadas: {memory?.reviewed_sources.confirmado ?? 0} confirmadas ·
              {memory?.reviewed_sources.descartado ?? 0} descartadas · {memory?.reviewed_sources.desactualizado ?? 0}{" "}
              desactualizadas
            </p>
          </div>
          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <BrainCircuit className="size-4" />
              <span className="font-medium">Qwen autohospedado</span>
              <Badge variant={model?.verified && model.active_for_nandutest ? "default" : "outline"}>
                {modelLabel}
              </Badge>
            </div>
            <p className="text-muted-foreground">{model?.reason || "Consultando configuración..."}</p>
            <p className="text-muted-foreground text-xs">Modelo: {model?.model || "Sin conexión privada"}</p>
            <p className="text-muted-foreground text-xs">
              El perfil GPT externo continúa activo hasta validar y seleccionar el modelo autohospedado.
            </p>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void testSharedModel()}
              disabled={!model?.configured || testing}
            >
              <ShieldCheck className="size-4" />
              {testing ? "Probando Qwen (máx. 30 s)..." : "Probar inferencia compartida"}
            </Button>
            {modelResult && (
              <p role="status" aria-live="polite" className="text-muted-foreground text-xs">
                {modelResult}
              </p>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <p className="font-medium">Consultar evidencia autorizada</p>
          <div className="flex flex-wrap gap-2">
            <div className="min-w-52 flex-1">
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                maxLength={180}
                placeholder="Ej.: controles MFA del proyecto de prueba"
                disabled={!memory?.enabled}
                onKeyDown={(event) => {
                  if (event.key === "Enter") void search();
                }}
              />
            </div>
            <Button size="sm" onClick={() => void search()} disabled={!memory?.enabled || !query.trim() || searching}>
              <Search className="size-4" /> {searching ? "Buscando..." : "Consultar memoria"}
            </Button>
          </div>
          <p className="text-muted-foreground text-xs">
            No ingresar contraseñas, datos personales ni documentos completos. El servidor aplica una cuota máxima de 20
            consultas/minuto, 200/día y dos solicitudes simultáneas; caché temporal de 60 segundos.
          </p>
        </div>

        {searchResult && (
          <div className="space-y-2">
            <p className="font-medium">
              Fuentes recuperadas ({searchResult.items.length}) {searchResult.cache_hit ? "· Desde caché" : ""}
            </p>
            {searchResult.items.map((item) => (
              <div key={item.id} className="space-y-2 rounded-lg border p-3">
                <code className="text-muted-foreground text-xs">{item.id}</code>
                <p className="whitespace-pre-wrap break-words">{item.content}</p>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={reviewing === item.id}
                    onClick={() => void review(item.id, "confirmado")}
                  >
                    Confirmar fuente
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={reviewing === item.id}
                    onClick={() => void review(item.id, "descartado")}
                  >
                    Descartar
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={reviewing === item.id}
                    onClick={() => void review(item.id, "desactualizado")}
                  >
                    Desactualizada
                  </Button>
                </div>
              </div>
            ))}
            {searchResult.items.length === 0 && (
              <p className="text-muted-foreground text-xs">No hay resultados válidos para este ámbito.</p>
            )}
          </div>
        )}
        <p className="text-muted-foreground text-xs">
          La memoria mejora la selección de fuentes con validación humana; no cambia los pesos de Qwen. La reserva
          global de consultas entre Ñandutest, Tenonderã y Getangiru requiere un gateway único todavía no habilitado.
        </p>
      </CardContent>
    </Card>
  );
}
