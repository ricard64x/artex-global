"use client";

import * as React from "react";

import Link from "next/link";

import { RefreshCw, Search, ShieldCheck } from "lucide-react";

import { RuntimeLLMStatus } from "@/components/ndt/runtime-llm-status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { RuntimeInventory } from "@/lib/runtime-inventory";

export default function SecurityInventoryPage() {
  const [inventory, setInventory] = React.useState<RuntimeInventory | null>(null);
  const [query, setQuery] = React.useState("");
  const [installedOnly, setInstalledOnly] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const reload = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setInventory(await api.runtimeInventory());
    } catch (caught) {
      setError(String(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  const filtered = (inventory?.tools ?? []).filter((tool) => {
    const matches = [tool.name, tool.command, tool.category, tool.description]
      .join(" ")
      .toLowerCase()
      .includes(query.toLowerCase().trim());
    return matches && (!installedOnly || tool.installed);
  });

  return (
    <div className="flex flex-1 flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <ShieldCheck className="size-5" /> Inventario de seguridad
          </h1>
          <p className="text-muted-foreground text-sm">
            Herramientas realmente detectadas en el servidor, sin ejecutar escaneos ni comandos.
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void reload()} disabled={loading}>
          <RefreshCw className="size-4" /> {loading ? "Verificando..." : "Actualizar inventario"}
        </Button>
      </div>
      <RuntimeLLMStatus />
      <Card>
        <CardHeader className="space-y-3">
          <CardTitle>Herramientas disponibles</CardTitle>
          <CardDescription>
            {inventory
              ? `${inventory.installed_count} instaladas de ${inventory.total_tools} verificadas.`
              : "Consultando los binarios del servidor..."}
          </CardDescription>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-52 flex-1">
              <Search className="text-muted-foreground absolute left-2.5 top-2.5 size-4" />
              <Input
                className="pl-8"
                placeholder="Buscar herramientas o categorías..."
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            <Button
              variant={installedOnly ? "default" : "outline"}
              size="sm"
              onClick={() => setInstalledOnly(!installedOnly)}
            >
              {installedOnly ? "Mostrando instaladas" : "Mostrar solo instaladas"}
            </Button>
          </div>
          {error && <p className="text-destructive text-sm">{error}</p>}
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {filtered.map((tool) => (
              <div className="rounded-lg border p-3" key={tool.command}>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-medium">{tool.name}</h3>
                    <code className="text-muted-foreground text-xs">{tool.command}</code>
                  </div>
                  <Badge variant={tool.installed ? "default" : "outline"}>
                    {tool.installed ? "Instalada" : "No instalada"}
                  </Badge>
                </div>
                <p className="text-muted-foreground mt-2 text-xs">{tool.description}</p>
                <div className="mt-2 flex gap-2">
                  <Badge variant="secondary">{tool.category}</Badge>
                  <Badge variant="outline">{tool.risk}</Badge>
                </div>
              </div>
            ))}
            {!loading && filtered.length === 0 && (
              <p className="text-muted-foreground text-sm">No hay herramientas que coincidan con los filtros.</p>
            )}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Administración y ampliación del catálogo</CardTitle>
          <CardDescription>
            El inventario inspecciona el contenedor activo. Agregar software requiere una imagen validada y despliegue
            controlado.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            Los analizadores de código pesados (Semgrep y Trivy) deben mantenerse en ejecutores aislados y de uso
            temporal para no sobrecargar Fly.io.
          </p>
          <p>
            Herramienta instalada no significa conectada a un agente. Toda prueba activa requiere alcance autorizado y
            controles de ejecución.
          </p>
          <Link href="/system/tools" className="text-primary underline underline-offset-4">
            Gestionar herramientas y permisos de agentes
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}
