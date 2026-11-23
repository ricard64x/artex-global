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
  const [reviewing, setReviewing] = React.useState("");
  const [modelResult, setModelResult] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    setLoading(true);
    try {
      setStatus(await api.getangiruStatus());
    } catch (error) {
      toast.error("No se pudo obtener el estado de Getangiru: " + String(error));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

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

  async function testSharedModel() {
    if (testing) return;
    setTesting(true);
    setModelResult(null);
    try {
      const result = await api.getangiruSharedModelTest();
      setModelResult("Inferencia de prueba correcta: " + String(result.latency_ms) + " ms.");
      await refresh();
    } catch (error) {
      setModelResult("No se verificó la inferencia: " + String(error));
    } finally {
      setTesting(false);
    }
  }

  const memory = status?.memory;
  const model = status?.model;

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
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Database className="size-4" />
              <span className="font-medium">Memoria Getangiru</span>
              <Badge variant={memory?.connected ? "default" : "outline"}>
                {memory?.connected ? "Conexión comprobada" : memory?.enabled ? "Configurada · sin probar" : "Desconectada"}
              </Badge>
            </div>
            <p className="text-muted-foreground">{memory?.reason || "Consultando configuración..."}</p>
            <p className="text-muted-foreground text-xs">{memory?.scope || "Ámbito todavía no configurado"}</p>
            <p className="text-muted-foreground text-xs">
              Consultas: {memory?.metrics.requests ?? 0} · Caché: {memory?.metrics.cache_hits ?? 0} ·
              Latencia p95: {memory?.metrics.p95_ms ?? 0} ms
            </p>
            <p className="text-muted-foreground text-xs">
              Revisadas: {memory?.reviewed_sources.confirmado ?? 0} confirmadas ·
              {memory?.reviewed_sources.descartado ?? 0} descartadas ·
              {memory?.reviewed_sources.desactualizado ?? 0} desactualizadas
            </p>
          </div>
          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <BrainCircuit className="size-4" />
              <span className="font-medium">Qwen autohospedado</span>
              <Badge variant={model?.verified && model.active_for_nandutest ? "default" : "outline"}>
                {model?.verified && model.active_for_nandutest
                  ? "Activo y probado"
                  : model?.verified
                    ? "Probado · no seleccionado"
                    : "Sin inferencia verificada"}
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
              {testing ? "Probando modelo..." : "Probar inferencia compartida"}
            </Button>
            {modelResult && <p className="text-muted-foreground text-xs">{modelResult}</p>}
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
            <Button
              size="sm"
              onClick={() => void search()}
              disabled={!memory?.enabled || !query.trim() || searching}
            >
              <Search className="size-4" /> {searching ? "Buscando..." : "Consultar memoria"}
            </Button>
          </div>
          <p className="text-muted-foreground text-xs">
            No ingresar contraseñas, datos personales ni documentos completos. El servidor aplica una cuota máxima
            de 20 consultas/minuto, 200/día y dos solicitudes simultáneas; caché temporal de 60 segundos.
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
