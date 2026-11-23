package server

// Controlled LLM routing for Ñandutest.
// Reuses the existing profile/circuit-breaker engine; never exposes provider secrets.
import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/Autumn-27/artex/db"
)

var nandutestRoutingMu sync.Mutex

const qwenManagedProfileName = "Qwen local · Tenonderã (Ñandutest)"

func matchLocalProfile(p *db.LLMProfile, c *localModelService) bool {
    return p != nil && c != nil &&
        strings.TrimRight(p.BaseURL, "/") == strings.TrimRight(c.baseURL, "/") &&
        p.Model == c.model
}
func findRoutingProfiles(profiles []*db.LLMProfile, cfg *localModelService) (local, external *db.LLMProfile) {
    for _, p := range profiles {
        if matchLocalProfile(p, cfg) { local = p; continue }
        if p.APIKeyHint == "" { continue }
        text := strings.ToLower(p.Name+" "+p.BaseURL)
        if strings.Contains(text, "openai") || strings.Contains(text, "chatgpt") {
            if external == nil || p.IsDefault { external = p }
        }
    }
    return
}
func (s *Server) routingStatus() map[string]any {
    cfg, _ := sharedModelSettings()
    profiles, err := s.m.pg.ListProfiles()
    if err != nil { return map[string]any{"error":"No se pueden consultar perfiles"} }
    local, external := findRoutingProfiles(profiles, cfg)
    active := "none"
    if local != nil && local.IsDefault { active = "qwen" }
    if external != nil && external.IsDefault { active = "openai" }
    poolEnabled := s.m.LLMPoolEnabled()
    mode := active
    if poolEnabled && active != "none" { mode = active+"_failover" }
    return map[string]any{
        "mode":mode, "primary":active, "failover":poolEnabled,
        "qwen_configured":cfg!=nil, "qwen_profile":local!=nil,
        "openai_profile":external!=nil,
        "local_model":func()string{if cfg!=nil{return cfg.model};return ""}(),
        "note":"El perfil primario sirve solicitudes generales sin fijación; tareas o agentes con perfil explícito pueden conservar su selección.",
    }
}
func (s *Server) getNandutestRouting(w http.ResponseWriter, r *http.Request) {
    if s.pg(w)==nil {return}
    writeJSON(w,200,s.routingStatus())
}
func checkQwenBeforeActivation(ctx context.Context, cfg *localModelService) error {
    if cfg==nil {return fmt.Errorf("Qwen privado no configurado")}
    body:=strings.NewReader(`{"model":"`+cfg.model+`","messages":[{"role":"user","content":"Responde OK"}],"stream":false,"max_tokens":16,"temperature":0}`)
    c,cancel:=context.WithTimeout(ctx,12*time.Second)
    defer cancel()
    req,err:=http.NewRequestWithContext(c,http.MethodPost,cfg.baseURL+"/chat/completions",body)
    if err!=nil{return err}
    req.Header.Set("Authorization","Bearer "+cfg.token)
    req.Header.Set("Content-Type","application/json")
    resp,err:=boundedServiceClient(12*time.Second).Do(req)
    if err!=nil{return fmt.Errorf("Qwen no responde")}
    defer resp.Body.Close()
    if resp.StatusCode!=200{return fmt.Errorf("Qwen rechazó inferencia (HTTP %d)",resp.StatusCode)}
    var reply struct {Choices []struct {Message struct {Content string `json:"content"`} `json:"message"`} `json:"choices"`}
    if json.NewDecoder(http.MaxBytesReader(nil,resp.Body,32768)).Decode(&reply)!=nil || len(reply.Choices)==0 || strings.TrimSpace(reply.Choices[0].Message.Content)=="" {
       return fmt.Errorf("Qwen no devolvió una respuesta válida")
    }
    return nil
}
func (s *Server) setNandutestRouting(w http.ResponseWriter,r *http.Request) {
    if s.pg(w)==nil {return}
    var in struct{ Mode string `json:"mode"` }
    if err:=decode(r,&in);err!=nil {writeErr(w,400,"Modo inválido");return}
    switch in.Mode {
    case "qwen","openai","qwen_failover","openai_failover":
    default:writeErr(w,422,"Elegí Qwen, OpenAI o uno de los dos modos de failover");return
    }
    nandutestRoutingMu.Lock()
    defer nandutestRoutingMu.Unlock()
    cfg,errText:=sharedModelSettings()
    if cfg==nil {writeErr(w,503,errText);return}
    profiles,err:=s.m.pg.ListProfiles()
    if err!=nil {writeErr(w,500,"No se pudo consultar perfiles");return}
    local,external:=findRoutingProfiles(profiles,cfg)
    if external==nil {writeErr(w,409,"No hay perfil OpenAI con credencial registrada; se conserva el modelo actual");return}
    openai,err:=s.m.pg.ProfileByID(external.ID)
    if err!=nil || openai==nil || len(openai.APIKey)<8 {writeErr(w,409,"OpenAI no dispone de una credencial válida");return}
    localPrimary:=strings.HasPrefix(in.Mode,"qwen")
    failover:=strings.HasSuffix(in.Mode,"_failover")
    if localPrimary {
        if err:=checkQwenBeforeActivation(r.Context(),cfg);err!=nil {writeErr(w,503,err.Error());return}
    }
    // Only the explicit local+OpenAI pair may participate in automatic fallback.
    // Do not unexpectedly route authorized prompts to unrelated provider profiles.
    if failover {
        for _,p:=range profiles {
            if p.APIKeyHint!="" && !p.PoolExclude && p.ID!=external.ID && (local==nil || p.ID!=local.ID) {
                writeErr(w,409,"Hay otros proveedores habilitados para failover. Excluilos del pool antes de activar el par Qwen/OpenAI.");return
            }
        }
    }
    if local==nil {
        id,err:=s.m.pg.SaveProfile(&db.LLMProfile{
            Name:qwenManagedProfileName,Format:"openai",BaseURL:cfg.baseURL,
            Model:cfg.model,APIKey:cfg.token,Streaming:false,MaxTokens:256,
            ContextWindowK:4,RatePerMinute:8,RatePerSecond:0.13,Priority:100,
        })
        if err!=nil {writeErr(w,500,"No se pudo registrar Qwen");return}
        local=&db.LLMProfile{ID:id}
    }
    target:=external.ID
    if localPrimary {target=local.ID}
    if err:=s.m.pg.SetActiveProfile(target);err!=nil {writeErr(w,500,"No se pudo cambiar el modelo primario");return}
    if err:=s.m.SetLLMPoolEnabled(failover);err!=nil {writeErr(w,500,"No se pudo ajustar failover");return}
    if err:=s.m.SetLLMPoolBindFallback(failover);err!=nil {writeErr(w,500,"No se pudo ajustar failover de agentes fijados");return}
    s.invalidateProfileAgents()
    s.reapplyActiveProfile()
    writeJSON(w,200,s.routingStatus())
}

// Supported opt-in bootstrap for guarded deployment. Keep disabled by default.
// No external account or secret is accepted through the request URL.
func (s *Server) bootstrapNandutestRouting() {
    if os.Getenv("NANDUTEST_ROUTING_BOOTSTRAP") != "qwen_failover" {return}
    // Bootstrapping still requires an explicit live inference, via the same
    // private gateway validation, before changing production routing.
    // Intentional no-op when the application is started without an authenticated
    // rollout procedure; operators use the routing API to commit this change.
}
