package server

// Multiusuario Ñandutest: la cuenta ARTEX sigue siendo el único superadministrador.
// Los usuarios delegados son de lectura en la fase piloto, con autorización
// denegada por defecto para ejecuciones, cambios de alcance y configuración.
import (
 "crypto/subtle"
 "fmt"
 "net/http"
 "os"
 "regexp"
 "strconv"
 "strings"
 "time"
 "unicode/utf8"

 "github.com/golang-jwt/jwt/v5"
 "golang.org/x/crypto/bcrypt"
)

type memberClaims struct {
 Username string `json:"username"`
 Role string `json:"role"`
 Version int64 `json:"version"`
 jwt.RegisteredClaims
}

type memberIdentity struct {
 ID int64
 Username string
 Role string
 Version int64
}

type managedUser struct {
 ID int64 `json:"id"`
 Username string `json:"username"`
 Name string `json:"name"`
 Email string `json:"email"`
 Role string `json:"role"`
 Enabled bool `json:"enabled"`
 CreatedAt time.Time `json:"created_at"`
}

var validManagedUsername = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{2,63}$`)

// Token signatures use the dedicated file key; token_version changes on every
// privileged account mutation and is rechecked in PostgreSQL on every request.
func (s *Server) issueMemberJWT(p memberIdentity) (string, error) {
 now := time.Now()
 return jwt.NewWithClaims(jwt.SigningMethodHS256, memberClaims{
  Username: p.Username, Role: p.Role, Version: p.Version,
  RegisteredClaims: jwt.RegisteredClaims{
   Subject: fmt.Sprintf("member:%d", p.ID),
   IssuedAt: jwt.NewNumericDate(now),
   ExpiresAt: jwt.NewNumericDate(now.Add(jwtTTL)),
  },
 }).SignedString(s.jwtKey)
}

func (s *Server) memberFromToken(token string) (memberIdentity, bool) {
 var empty memberIdentity
 if token == "" || s.m == nil || s.m.PG() == nil {return empty,false}
 claims := &memberClaims{}
 parsed,err := jwt.ParseWithClaims(token,claims,func(t *jwt.Token)(any,error){return s.jwtKey,nil},jwt.WithValidMethods([]string{"HS256"}))
 if err != nil || !parsed.Valid || !strings.HasPrefix(claims.Subject,"member:") {return empty,false}
 id,err:=strconv.ParseInt(strings.TrimPrefix(claims.Subject,"member:"),10,64)
 if err!=nil || id<=0{return empty,false}
 var p memberIdentity
 var enabled bool
 err=s.m.PG().QueryRow("SELECT id,username,role,enabled,token_version FROM ndt_users WHERE id=$1",id).
  Scan(&p.ID,&p.Username,&p.Role,&enabled,&p.Version)
 if err!=nil || !enabled || (p.Role!="operator"&&p.Role!="auditor") || p.Version!=claims.Version ||
  subtle.ConstantTimeCompare([]byte(p.Username),[]byte(claims.Username)) != 1 {return empty,false}
 return p,true
}

func (s *Server) authPrincipal(token string) (memberIdentity,bool) {
 if p,ok:=s.memberFromToken(token);ok{return p,true}
 if s.verifyToken(token) {return memberIdentity{Username:"ARTEX",Role:"superadmin"},true}
 return memberIdentity{},false
}

// Read-only delegated roles: explicit minimal allowlist, no prefix wildcards.
// A GET can still expose tools, secrets, raw evidence or modify run state.
var delegatedExactReads = map[string]bool{
	"/api/stats": true,
	"/api/report": true,
	"/api/tasks": true,
	"/api/task-categories": true,
	"/api/task-templates": true,
	"/api/assets": true,
	"/api/assets/counts": true,
	"/api/companies": true,
	"/api/exploration/findings": true,
	"/api/exploration/findings/groups": true,
	"/api/exploration/findings/stats": true,
	"/api/exploration/findings/asset-tree": true,
	"/api/tokens/usage": true,
	"/api/tokens/daily": true,
	"/api/commands/stats": true,
}

// The ID predicate deliberately excludes slashes, dots, encodings and wildcards.
var delegatedResourceID = regexp.MustCompile("^[A-Za-z0-9_-]{1,128}$")

func delegatedReadAllowed(path string) bool {
	if delegatedExactReads[path] {
		return true
	}
	segments := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
	if len(segments) == 2 && delegatedResourceID.MatchString(segments[1]) {
		return segments[0] == "tasks" || segments[0] == "companies"
	}
	if len(segments) == 3 && segments[0] == "tasks" && delegatedResourceID.MatchString(segments[1]) {
		switch segments[2] {
		case "coverage", "coverage-graph", "asset-refs":
			return true
		}
	}
	if len(segments) == 3 && segments[0] == "exploration" && segments[1] == "findings" &&
		delegatedResourceID.MatchString(segments[2]) {
		// Do not expose /retests, /lineage or raw evidence to read-only users.
		return segments[2] != "export"
	}
	return false
}

func memberPasswordOK(password string) bool {
 return utf8.RuneCountInString(password)>=12 && len(password)<=maxPasswordBytes
}

func managedRole(role string) bool {return role=="operator"||role=="auditor"}

func (s *Server) memberLogin(w http.ResponseWriter,r *http.Request,username,password,key string) {
 if !delegatedPilotEnabled() { s.limiter().fail(key);writeErr(w,401,authErrBadCredential);return }
 pg:=s.m.PG()
 var p memberIdentity
 var hashed string
 var enabled bool
 err:=pg.QueryRow("SELECT id,username,role,enabled,token_version,password_hash FROM ndt_users WHERE lower(username)=lower($1)",username).
  Scan(&p.ID,&p.Username,&p.Role,&enabled,&p.Version,&hashed)
 // Always perform a bcrypt comparison to avoid a quick username oracle.
 if err!=nil{hashed="$2a$10$Yx5g5iChzBAFKH2TD5b9hukPZXkeLKi8sOZrAPFwYAciv7MuoIi/a"}
 good:=bcrypt.CompareHashAndPassword([]byte(hashed),[]byte(password))==nil
 if err!=nil||!enabled||!good||!managedRole(p.Role) {
  s.limiter().fail(key)
  writeErr(w,401,authErrBadCredential)
  return
 }
 s.limiter().reset(key)
 tok,err:=s.issueMemberJWT(p)
 if err!=nil{writeErr(w,500,authErrTokenGen);return}
 writeJSON(w,200,map[string]any{"token":tok})
}

func (s *Server) authMe(w http.ResponseWriter,r *http.Request) {
 p,ok:=s.authPrincipal(extractToken(r))
 if !ok{writeErr(w,401,authErrUnauthorized);return}
 writeJSON(w,200,map[string]any{"username":p.Username,"role":p.Role,"id":p.ID})
}

func (s *Server) memberChangePassword(w http.ResponseWriter,r *http.Request) {
 p,ok:=s.memberFromToken(extractToken(r))
 if !ok{writeErr(w,401,authErrUnauthorized);return}
 key:=clientKey(r)
 if !s.limiter().allow(key){writeErr(w,429,authErrTooManyAttempts);return}
 var req struct{OldPassword string `json:"old_password"`;NewPassword string `json:"new_password"`}
 if err:=decode(r,&req);err!=nil{writeErr(w,400,"Solicitud inválida");return}
 if !memberPasswordOK(req.NewPassword){writeErr(w,400,"La contraseña debe tener entre 12 caracteres y 72 bytes");return}
 var old string
 if err:=s.m.PG().QueryRow("SELECT password_hash FROM ndt_users WHERE id=$1 AND enabled=true",p.ID).Scan(&old);err!=nil{
  writeErr(w,401,authErrUnauthorized);return
 }
 if bcrypt.CompareHashAndPassword([]byte(old),[]byte(req.OldPassword))!=nil{
  s.limiter().fail(key);writeErr(w,401,authErrBadCredential);return
 }
 hash,err:=bcrypt.GenerateFromPassword([]byte(req.NewPassword),bcrypt.DefaultCost)
 if err!=nil{writeErr(w,500,"Error de contraseña");return}
 row:=s.m.PG().QueryRow("UPDATE ndt_users SET password_hash=$1,token_version=token_version+1 WHERE id=$2 AND password_hash=$3 RETURNING token_version",string(hash),p.ID,old)
 if err:=row.Scan(&p.Version);err!=nil{writeErr(w,409,"La contraseña fue modificada en otra sesión");return}
 s.limiter().reset(key)
 tok,err:=s.issueMemberJWT(p)
 if err!=nil{writeErr(w,500,authErrTokenGen);return}
 writeJSON(w,200,map[string]any{"ok":true,"token":tok})
}

func (s *Server) superAdminFor(r *http.Request) bool {
 // Avoid reading unverified JWT role claims; admin JWT is signed by a key
 // derived from the legacy password hash and verified server side.
 return s.verifyToken(extractToken(r))
}

func (s *Server) manageUsers(w http.ResponseWriter,r *http.Request){
 if !s.superAdminFor(r){writeErr(w,403,"Solo el administrador privilegiado puede gestionar usuarios");return}
 pg:=s.m.PG()
 if r.Method=="GET" {
  rows,err:=pg.Query("SELECT id,username,name,email,role,enabled,created_at FROM ndt_users ORDER BY id")
  if err!=nil{writeErr(w,500,"No se pudo consultar usuarios");return}
  defer rows.Close()
  users:=[]managedUser{}
  for rows.Next(){
   var u managedUser
   if err:=rows.Scan(&u.ID,&u.Username,&u.Name,&u.Email,&u.Role,&u.Enabled,&u.CreatedAt);err!=nil{
    writeErr(w,500,"Error al consultar usuarios");return
   }
   users=append(users,u)
  }
  if rows.Err()!=nil{writeErr(w,500,"Error al consultar usuarios");return}
  writeJSON(w,200,map[string]any{"users":users});return
 }
 var req struct{
  Username string `json:"username"`
  Name string `json:"name"`
  Email string `json:"email"`
  Role string `json:"role"`
  Password string `json:"password"`
 }
 if err:=decode(r,&req);err!=nil{writeErr(w,400,"Solicitud inválida");return}
 req.Username=strings.TrimSpace(req.Username)
 req.Name=strings.TrimSpace(req.Name)
 req.Email=strings.ToLower(strings.TrimSpace(req.Email))
 if !validManagedUsername.MatchString(req.Username)||strings.EqualFold(req.Username,"ARTEX")||
  len(req.Name)==0||len(req.Name)>120||len(req.Email)<3||len(req.Email)>254||!strings.Contains(req.Email,"@")||
  !managedRole(req.Role)||!memberPasswordOK(req.Password) {
  writeErr(w,400,"Datos inválidos. Contraseña mínima de 12 caracteres, máximo 72 bytes");return
 }
 hash,err:=bcrypt.GenerateFromPassword([]byte(req.Password),bcrypt.DefaultCost)
 if err!=nil{writeErr(w,500,"Error al proteger la contraseña");return}
 var id int64
 err=pg.QueryRow("INSERT INTO ndt_users(username,name,email,role,password_hash) VALUES($1,$2,$3,$4,$5) RETURNING id",
  req.Username,req.Name,req.Email,req.Role,string(hash)).Scan(&id)
 if err!=nil{writeErr(w,409,"Nombre de usuario o email ya existente");return}
 s.auditUserAction("create",id,r)
 writeJSON(w,201,map[string]any{"id":id,"ok":true})
}

func (s *Server) manageUser(w http.ResponseWriter,r *http.Request){
 if !s.superAdminFor(r){writeErr(w,403,"Solo el administrador privilegiado puede gestionar usuarios");return}
 id,err:=strconv.ParseInt(r.PathValue("id"),10,64)
 if err!=nil||id<=0{writeErr(w,400,"ID inválido");return}
 pg:=s.m.PG()
 if r.Method=="DELETE"{
  result,err:=pg.Exec("UPDATE ndt_users SET enabled=false,token_version=token_version+1 WHERE id=$1",id)
  if err!=nil{writeErr(w,500,"No se pudo desactivar");return}
  n,_:=result.RowsAffected()
  if n==0{writeErr(w,404,"Usuario no encontrado");return}
  s.auditUserAction("disable",id,r)
  writeJSON(w,200,map[string]any{"ok":true});return
 }
 var req struct{Role string `json:"role"`; Enabled *bool `json:"enabled"`}
 if err:=decode(r,&req);err!=nil||!managedRole(req.Role)||req.Enabled==nil{
  writeErr(w,400,"Rol o estado inválido");return
 }
 result,err:=pg.Exec("UPDATE ndt_users SET role=$1,enabled=$2,token_version=token_version+1 WHERE id=$3",req.Role,*req.Enabled,id)
 if err!=nil{writeErr(w,500,"No se pudo actualizar");return}
 n,_:=result.RowsAffected()
 if n==0{writeErr(w,404,"Usuario no encontrado");return}
 s.auditUserAction("change_role_or_status",id,r)
 writeJSON(w,200,map[string]any{"ok":true})
}

func (s *Server) resetUserPassword(w http.ResponseWriter,r *http.Request){
 if !s.superAdminFor(r){writeErr(w,403,"Solo administrador");return}
 id,err:=strconv.ParseInt(r.PathValue("id"),10,64)
 if err!=nil||id<=0{writeErr(w,400,"ID inválido");return}
 var req struct{Password string `json:"password"`}
 if err:=decode(r,&req);err!=nil||!memberPasswordOK(req.Password){
  writeErr(w,400,"Contraseña inválida: mínimo 12 caracteres, máximo 72 bytes");return
 }
 hash,err:=bcrypt.GenerateFromPassword([]byte(req.Password),bcrypt.DefaultCost)
 if err!=nil{writeErr(w,500,"Error al proteger contraseña");return}
 res,err:=s.m.PG().Exec("UPDATE ndt_users SET password_hash=$1,token_version=token_version+1 WHERE id=$2",string(hash),id)
 if err!=nil{writeErr(w,500,"No se pudo actualizar contraseña");return}
 n,_:=res.RowsAffected()
 if n==0{writeErr(w,404,"Usuario no encontrado");return}
 s.auditUserAction("reset_password",id,r)
 writeJSON(w,200,map[string]any{"ok":true})
}

func (s *Server) auditUserAction(action string,id int64,r *http.Request){
 if s.m==nil||s.m.PG()==nil{return}
 _,err:=s.m.PG().Exec("INSERT INTO ndt_user_audit(actor,action,target_id,ip_address) VALUES($1,$2,$3,$4)",
  "ARTEX",action,id,clientKey(r))
 if err!=nil{ /* do not leak customer data or credentials into logs */ }
}


// delegatedPilotEnabled is a temporary break-glass switch. In production it
// MUST stay off until resources are filtered by company and project in the DB,
// not only through the UI. Admin management remains available.
func delegatedPilotEnabled() bool {
 return os.Getenv("NANDUTEST_DELEGATED_ENABLED") == "1"
}
