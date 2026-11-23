export interface RuntimeSecurityTool {
  name: string;
  command: string;
  category: string;
  description: string;
  risk: string;
  installed: boolean;
}

export interface RuntimeLLMInfo {
  configured: boolean;
  origin: "local" | "remoto" | "no_configurado";
  profile_id?: number;
  profile_name?: string;
  provider?: string;
  model?: string;
  base_url?: string;
  endpoint_checked: boolean;
  endpoint_online: boolean;
  model_installed: boolean;
  inference_checked: boolean;
  diagnostic: string;
}

export interface RuntimeInventory {
  llm: RuntimeLLMInfo;
  tools: RuntimeSecurityTool[];
  installed_count: number;
  total_tools: number;
  tools_note: string;
}
