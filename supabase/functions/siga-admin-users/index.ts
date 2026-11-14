import { createSupabaseContext } from "npm:@supabase/server";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

function respond(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

const SIGA_MODULE_KEYS = new Set(["members", "meetings", "finance", "bank_accounts", "assets", "agenda", "reports"]);
const PROTECTED_CENTRAL_ADMIN_ID = "09ce87fb-ee13-44a5-9975-b32542169527";
const PROTECTED_LEGACY_EMAIL = "adm.centralcontabil@hotmail.com";
const PROTECTED_LEGACY_USER_ID = "1e3457fb-2298-462b-8812-4795e01e4f68";

function isProtectedUser(user: any) {
  return user.id === PROTECTED_CENTRAL_ADMIN_ID ||
    user.id === PROTECTED_LEGACY_USER_ID ||
    String(user.email ?? "").trim().toLowerCase() === PROTECTED_LEGACY_EMAIL ||
    user.app_metadata?.app === "ccj_digital";
}

function safeUser(user: any) {
  return {
    id: user.id,
    email: user.email ?? "",
    full_name: user.user_metadata?.full_name ?? "",
    role: user.app_metadata?.role === "admin" ? "admin" : "user",
    protected: isProtectedUser(user),
    created_at: user.created_at ?? null,
    email_confirmed_at: user.email_confirmed_at ?? null,
  };
}

async function listAllUsers(admin: any) {
  const users: any[] = [];
  const perPage = 1000;
  for (let page = 1; page <= 50; page += 1) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const batch = data?.users ?? [];
    users.push(...batch);
    if (batch.length < perPage) break;
  }
  return users;
}

function isValidEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "Método não permitido." }, 405);

  const contextResult = await createSupabaseContext(req, { auth: "user" });
  if (contextResult.error || !contextResult.data) {
    return respond({ error: "Sessão inválida. Entre novamente no SIGA." }, 401);
  }

  const { supabase, supabaseAdmin } = contextResult.data;
  const bearer = req.headers.get("Authorization") ?? "";
  const token = bearer.replace(/^Bearer\s+/i, "");
  const { data: actorResult, error: actorError } = await supabase.auth.getUser(token);
  const actor = actorResult?.user;
  if (actorError || !actor) return respond({ error: "Sessão inválida. Entre novamente no SIGA." }, 401);
  if (actor.app_metadata?.role !== "admin") {
    return respond({ error: "Somente administradores podem gerenciar contas e permissões." }, 403);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return respond({ error: "Requisição inválida." }, 400);
  }
  const action = String(body.action ?? "");

  try {
    if (action === "list_users") {
      const users = await listAllUsers(supabaseAdmin);
      return respond({ users: users.map(safeUser) });
    }

    if (action === "create_user") {
      const fullName = String(body.fullName ?? "").trim();
      const email = String(body.email ?? "").trim().toLowerCase();
      const password = String(body.password ?? "");
      const role = String(body.role ?? "user");
      if (!fullName || fullName.length > 180) return respond({ error: "Informe um nome válido." }, 400);
      if (!isValidEmail(email) || email.length > 254) return respond({ error: "Informe um e-mail válido." }, 400);
      if (password.length < 8) return respond({ error: "A senha precisa ter pelo menos 8 caracteres." }, 400);
      if (role !== "user" && role !== "admin") return respond({ error: "Perfil inválido." }, 400);
      const { data, error } = await supabaseAdmin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: fullName },
        app_metadata: { role },
      });
      if (error) {
        const message = error.message.toLowerCase().includes("already") || error.message.toLowerCase().includes("registered")
          ? "Este e-mail já está cadastrado."
          : "Não foi possível cadastrar a conta. Confira o e-mail e a senha.";
        return respond({ error: message }, 400);
      }
      return respond({ user: safeUser(data.user) }, 201);
    }

    if (action === "update_user") {
      const userId = String(body.userId ?? "");
      const fullName = String(body.fullName ?? "").trim();
      const email = String(body.email ?? "").trim().toLowerCase();
      const password = typeof body.password === "string" ? body.password : "";
      const role = String(body.role ?? "user");
      if (!/^[0-9a-f-]{36}$/i.test(userId)) return respond({ error: "Conta inválida." }, 400);
      if (!fullName || fullName.length > 180) return respond({ error: "Informe um nome válido." }, 400);
      if (!isValidEmail(email) || email.length > 254) return respond({ error: "Informe um e-mail válido." }, 400);
      if (password.length > 0 && password.length < 8) return respond({ error: "A nova senha precisa ter pelo menos 8 caracteres." }, 400);
      if (role !== "user" && role !== "admin") return respond({ error: "Perfil inválido." }, 400);
      if (userId === actor.id && role !== "admin") {
        return respond({ error: "Não é permitido remover o próprio perfil de administrador." }, 400);
      }
      const { data: currentResult, error: currentError } = await supabaseAdmin.auth.admin.getUserById(userId);
      if (currentError || !currentResult.user) return respond({ error: "Conta não encontrada." }, 404);
      if (isProtectedUser(currentResult.user)) return respond({ error: "Esta conta está protegida e não pode ser alterada por esta tela." }, 403);
      if (currentResult.user.app_metadata?.role === "admin" && role !== "admin") {
        const allUsers = await listAllUsers(supabaseAdmin);
        const admins = allUsers.filter((user) => user.app_metadata?.role === "admin");
        if (admins.length <= 1) return respond({ error: "Mantenha pelo menos um administrador ativo." }, 400);
      }
      const currentUser = currentResult.user;
      const update: Record<string, unknown> = {
        email,
        email_confirm: true,
        user_metadata: { ...(currentUser.user_metadata ?? {}), full_name: fullName },
        app_metadata: { ...(currentUser.app_metadata ?? {}), role },
      };
      if (password) update.password = password;
      const { data, error } = await supabaseAdmin.auth.admin.updateUserById(userId, update);
      if (error) return respond({ error: "Não foi possível atualizar a conta. Confira o e-mail e a nova senha." }, 400);
      return respond({ user: safeUser(data.user) });
    }

    if (action === "list_assignments") {
      const { data, error } = await supabaseAdmin
        .from("siga_user_unit_permissions")
        .select("user_id,unit_id,permissions,granted_at")
        .order("granted_at", { ascending: false });
      if (error) throw error;
      return respond({ assignments: data ?? [] });
    }

    if (action === "list_module_permissions") {
      const { data, error } = await supabaseAdmin
        .from("siga_user_module_permissions")
        .select("user_id,modules,updated_at")
        .order("updated_at", { ascending: false });
      if (error) throw error;
      return respond({ permissions: data ?? [] });
    }

    if (action === "set_module_permissions") {
      const userId = String(body.userId ?? "");
      const requestedModules = body.modules;
      if (!/^[0-9a-f-]{36}$/i.test(userId)) return respond({ error: "Conta inválida." }, 400);
      if (!Array.isArray(requestedModules) || requestedModules.some((key) => typeof key !== "string" || !SIGA_MODULE_KEYS.has(key))) {
        return respond({ error: "Selecione módulos válidos." }, 400);
      }
      const { data: userResult, error: userError } = await supabaseAdmin.auth.admin.getUserById(userId);
      if (userError || !userResult.user) return respond({ error: "Usuário não encontrado." }, 404);
      const target = userResult.user;
      if (target.app_metadata?.role === "admin") return respond({ error: "Administradores têm acesso completo automaticamente." }, 400);
      if (isProtectedUser(target)) return respond({ error: "Esta conta está protegida e não pode ter os módulos alterados." }, 403);
      const modules = Object.fromEntries([...new Set(requestedModules)].map((key) => [key, true]));
      const { error } = await supabaseAdmin.from("siga_user_module_permissions").upsert({
        user_id: userId,
        modules,
        updated_by: actor.id,
        updated_at: new Date().toISOString(),
      }, { onConflict: "user_id" });
      if (error) throw error;
      return respond({ ok: true, user_id: userId, modules });
    }

    if (action === "grant_unit_access") {
      const userId = String(body.userId ?? "");
      const unitId = String(body.unitId ?? "");
      if (!/^[0-9a-f-]{36}$/i.test(userId) || !/^[0-9a-f-]{36}$/i.test(unitId)) {
        return respond({ error: "Selecione um usuário e uma unidade válidos." }, 400);
      }
      const { data: userResult, error: userError } = await supabaseAdmin.auth.admin.getUserById(userId);
      if (userError || !userResult.user) return respond({ error: "Usuário não encontrado." }, 404);
      if (userResult.user.app_metadata?.role === "admin") {
        return respond({ error: "Administradores já têm acesso a todas as unidades." }, 400);
      }
      if (isProtectedUser(userResult.user)) return respond({ error: "Esta conta está protegida e não pode ter unidades alteradas por esta tela." }, 403);
      const { data: unit, error: unitError } = await supabaseAdmin
        .from("siga_units")
        .select("id,is_active")
        .eq("id", unitId)
        .maybeSingle();
      if (unitError || !unit) return respond({ error: "Unidade não encontrada." }, 404);
      if (!unit.is_active) return respond({ error: "Ative a unidade antes de vinculá-la." }, 400);
      const { error } = await supabaseAdmin.from("siga_user_unit_permissions").upsert({
        user_id: userId,
        unit_id: unitId,
        permissions: { "units.read": true },
        granted_by: actor.id,
        granted_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      if (error) throw error;
      return respond({ ok: true });
    }

    if (action === "revoke_unit_access") {
      const userId = String(body.userId ?? "");
      const unitId = String(body.unitId ?? "");
      if (!/^[0-9a-f-]{36}$/i.test(userId) || !/^[0-9a-f-]{36}$/i.test(unitId)) {
        return respond({ error: "Vínculo inválido." }, 400);
      }
      const { data: userResult, error: userError } = await supabaseAdmin.auth.admin.getUserById(userId);
      if (userError || !userResult.user) return respond({ error: "Usuário não encontrado." }, 404);
      if (isProtectedUser(userResult.user)) return respond({ error: "Esta conta está protegida e não pode ter unidades alteradas por esta tela." }, 403);
      const { error } = await supabaseAdmin
        .from("siga_user_unit_permissions")
        .delete()
        .eq("user_id", userId)
        .eq("unit_id", unitId);
      if (error) throw error;
      return respond({ ok: true });
    }

    return respond({ error: "Ação administrativa desconhecida." }, 400);
  } catch {
    return respond({ error: "Não foi possível concluir a operação. Tente novamente." }, 500);
  }
});

