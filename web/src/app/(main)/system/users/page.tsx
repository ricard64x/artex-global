"use client";
import * as React from "react";
import { toast } from "sonner";
import { Users, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { http } from "@/lib/api";

type Role = "operator" | "auditor";
type User = { id:number; username:string; name:string; email:string; role:Role; enabled:boolean };
const EMPTY = {username:"",name:"",email:"",role:"auditor" as Role,password:""};

export default function UsersPage(){
 const [users,setUsers]=React.useState<User[]>([]);
 const [allowed,setAllowed]=React.useState<boolean|null>(null);
 const [busy,setBusy]=React.useState(false);
 const [form,setForm]=React.useState(EMPTY);
 const [resetId,setResetId]=React.useState<number|null>(null);
 const [newPassword,setNewPassword]=React.useState("");
 const reload=React.useCallback(async()=>{
  const me=await http<{role:string}>("/auth/me");
  if(me.role!=="superadmin"){setAllowed(false);return}
  setAllowed(true);
  const data=await http<{users:User[]}>("/users");
  setUsers(data.users??[]);
 },[]);
 React.useEffect(()=>{reload().catch((e:Error)=>{setAllowed(false);toast.error(e.message)})},[reload]);
 const run=async (fn:()=>Promise<unknown>)=>{
  if(busy)return;setBusy(true);
  try{await fn();await reload();toast.success("Cambio guardado; sesiones anteriores revocadas")}
  catch(e){toast.error((e as Error).message)}finally{setBusy(false)}
 };
 if(allowed===null)return <p className="p-6">Verificando permisos…</p>;
 if(!allowed)return <p className="p-6 text-destructive">Acceso reservado al administrador privilegiado ARTEX.</p>;
 return <main className="space-y-5 p-4 md:p-6">
  <h1 className="flex items-center gap-2 text-2xl font-semibold"><Users/> Gestión de usuarios</h1>
  <Card><CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck/> Administrador privilegiado: ARTEX</CardTitle></CardHeader>
   <CardContent className="text-sm text-muted-foreground">Esta cuenta está separada y no puede desactivarse ni degradarse aquí. Solo ARTEX administra configuración, modelos, herramientas y usuarios.</CardContent>
  </Card>
  <Card><CardHeader><CardTitle>Crear usuario delegado</CardTitle></CardHeader><CardContent>
   <form className="grid gap-3 md:grid-cols-3" onSubmit={e=>{e.preventDefault();void run(async()=>{await http("/users",{method:"POST",body:JSON.stringify(form)});setForm(EMPTY)})}}>
    <div><Label htmlFor="usr">Usuario</Label><Input id="usr" required minLength={3} value={form.username} onChange={e=>setForm({...form,username:e.target.value})}/></div>
    <div><Label htmlFor="fullname">Nombre completo</Label><Input id="fullname" required value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></div>
    <div><Label htmlFor="email">Correo electrónico</Label><Input id="email" required type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})}/></div>
    <div><Label htmlFor="role">Rol delegado</Label><select id="role" className="h-9 w-full rounded-md border bg-background px-3 text-sm" value={form.role} onChange={e=>setForm({...form,role:e.target.value as Role})}><option value="auditor">Auditor (lectura)</option><option value="operator">Operador (piloto supervisado)</option></select></div>
    <div><Label htmlFor="password">Clave inicial (mínimo 12 caracteres)</Label><Input id="password" required type="password" minLength={12} maxLength={72} autoComplete="new-password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}/></div>
    <div className="flex items-end"><Button type="submit" disabled={busy} className="w-full">Crear usuario</Button></div>
   </form>
  </CardContent></Card>
  <Card><CardHeader><CardTitle>Cuentas delegadas ({users.length})</CardTitle></CardHeader><CardContent className="space-y-3">
   <p className="text-sm text-muted-foreground">Fase piloto: ambos roles consultan información autorizada. La ejecución activa queda bloqueada hasta implementar permisos de alcance por usuario y tarea.</p>
   <div className="overflow-x-auto"><table className="w-full min-w-[650px] text-left text-sm">
    <thead><tr className="border-b"><th className="p-2">Usuario</th><th className="p-2">Nombre / email</th><th className="p-2">Rol</th><th className="p-2">Estado</th><th className="p-2">Acciones</th></tr></thead>
    <tbody>{users.map(u=><tr key={u.id} className="border-b">
     <td className="p-2 font-mono">{u.username}</td><td className="p-2">{u.name}<div className="text-xs text-muted-foreground">{u.email}</div></td>
     <td className="p-2"><select className="rounded-md border bg-background p-1" aria-label={"Rol de "+u.username} disabled={busy} value={u.role} onChange={e=>void run(()=>http("/users/"+u.id,{method:"PATCH",body:JSON.stringify({role:e.target.value,enabled:u.enabled})}))}><option value="auditor">Auditor</option><option value="operator">Operador</option></select></td>
     <td className="p-2">{u.enabled?"Activo":"Desactivado"}</td>
     <td className="flex gap-2 p-2"><Button variant="outline" size="sm" disabled={busy} onClick={()=>void run(()=>http("/users/"+u.id,{method:"PATCH",body:JSON.stringify({role:u.role,enabled:!u.enabled})}))}>{u.enabled?"Desactivar":"Activar"}</Button>
      <Button variant="outline" size="sm" onClick={()=>{setResetId(u.id);setNewPassword("")}}>Cambiar clave</Button></td>
    </tr>)}</tbody></table></div>
    {users.length===0&&<p className="text-sm text-muted-foreground">No hay usuarios delegados.</p>}
  </CardContent></Card>
  {resetId!==null&&<Card><CardHeader><CardTitle>Restablecer contraseña de usuario #{resetId}</CardTitle></CardHeader><CardContent className="flex flex-wrap items-end gap-2">
   <div className="flex-1 space-y-1"><Label htmlFor="reset-password">Nueva contraseña</Label><Input id="reset-password" type="password" minLength={12} maxLength={72} autoComplete="new-password" value={newPassword} onChange={e=>setNewPassword(e.target.value)}/></div>
   <Button disabled={busy||newPassword.length<12} onClick={()=>void run(async()=>{await http("/users/"+resetId+"/password",{method:"POST",body:JSON.stringify({password:newPassword})});setResetId(null);setNewPassword("")})}>Guardar y revocar sesiones</Button>
   <Button variant="ghost" onClick={()=>setResetId(null)}>Cancelar</Button>
  </CardContent></Card>}
 </main>
}
