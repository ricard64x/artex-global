"use client";

import * as React from "react";

import Link from "next/link";

import { AlertCircle, CheckCircle2, Cpu, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { RuntimeInventory } from "@/lib/runtime-inventory";

export function RuntimeLLMStatus() {
  const [runtime, setRuntime] = React.useState<RuntimeInventory | null>(null);
  const [checking, setChecking] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [result, setResult] = React.useState<{ ok: boolean; latency_ms?: number; error?: string } | null>(null);

  const refresh = React.useCallback(async () => {
    setChecking(true);
    try {
      setRuntime(await api.runtimeInventory());
      setResult(null);
    } catch (error) {
      toast.error("No se pudo consultar el estado del motor: " + String(error));
    } finally {
      setChecking(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const llm = runtime?.llm;
  const isLocal = llm?.origin === "local";
  const ready = isLocal && llm.endpoint_online && llm.model_installed;

  async function testInference() {
    if (!llm?.configured || !isLocal || testing) return;
    setTesting(true);
    setResult(null);
    try {
      const answer = await api.testLLM(
        llm.provider ?? "openai",
        llm.model ?? "",
        llm.base_url ?? "",
        "",
        "",
        "",
        "",
        llm.profile_id || undefined,
      );
      setResult({ ok: answer.ok, latency_ms: answer.latency_ms, error: answer.error });
      if (answer.ok) toast.success("Inferencia real comprobada correctamente");
    } catch (error) {
      setResult({ ok: false, error: String(error) });
    } finally {
      setTesting(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Cpu className="size-4" /> Estado real del motor de IA
        </CardTitle>
        <Button type="button" variant="outline" size="sm" onClick={() => void refresh()} disabled={checking}>
          <RefreshCw className="size-4" /> {checking ? "Verificando..." : "Actualizar"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">
            {!llm?.configured ? "Sin LLM configurado" : isLocal ? "Perfil local" : "Perfil externo"}
          </Badge>
          <Badge variant={ready ? "default" : "secondary"}>
            {ready ? "Motor y modelo disponibles" : llm?.configured ? "Inferencia sin verificar" : "Inactivo"}
          </Badge>
          {result?.ok && <Badge className="bg-emerald-700">Inferencia real verificada</Badge>}
        </div>
        <div className="grid gap-1 text-muted-foreground">
          <span>
            Modelo: <strong className="text-foreground">{llm?.model || "Sin configurar"}</strong>
          </span>
          <span>Perfil: {llm?.profile_name || "Predeterminado"}</span>
          <span>
            Origen:{" "}
            {llm?.origin === "local"
              ? "Servicio local / Ollama"
              : llm?.origin === "remoto"
                ? "Proveedor externo"
                : "No configurado"}
          </span>
          <span>{llm?.diagnostic || "Consultando configuración..."}</span>
        </div>
        {result?.ok ? (
          <p className="flex items-center gap-2 text-emerald-600">
            <CheckCircle2 className="size-4" /> Prueba de inferencia correcta en {result.latency_ms ?? "?"} ms.
          </p>
        ) : result ? (
          <p className="flex items-center gap-2 text-destructive">
            <AlertCircle className="size-4" /> Prueba fallida:{" "}
            {result.error || "El modelo no devolvió una respuesta válida"}.
          </p>
        ) : (
          <p className="text-muted-foreground text-xs">
            Un perfil guardado o un puerto disponible no prueban que el modelo genere respuestas.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3">
          <Button
            type="button"
            size="sm"
            onClick={() => void testInference()}
            disabled={!isLocal || !llm?.configured || testing}
          >
            {testing ? "Probando inferencia..." : "Probar inferencia local"}
          </Button>
          <Link href="/system/runtime-security" className="text-primary text-xs underline underline-offset-4">
            Ver inventario y diagnóstico
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}
