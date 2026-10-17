import { createSupabaseContext } from "npm:@supabase/server";
import {
  AUTH0_DOMAIN,
  ensureSigaIdentity,
  findSigaIdentity,
  isTrustedAuth0Claims,
  isValidEmail,
  normalizeEmail,
  SigaIdentityError,
  type SigaRole,
} from "../_shared/siga-auth0.ts";

const AUTH0_CONNECTION_NAME = Deno.env.get("AUTH0_CONNECTION_NAME") ?? "Username-Password-Authentication";
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

function respond(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

function isValidUUID(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function roleFrom(value: unknown): SigaRole {
  return value === "admin" ? "admin" : "user";
}

let tokenCache: { value: string; expiresAt: number } | null = null;

async function getManagementToken() {
  if (tokenCache && tokenCache.expiresAt > Date.now() + 60_000) return tokenCache.value;
  const clientId = Deno.env.get("AUTH0_M2M_CLIENT_ID");
  const clientSecret = Deno.env.get("AUTH0_M2M_CLIENT_SECRET");
  if (!clientId || !clientSecret) throw new Error("AUTH0_MANAGEMENT_NOT_CONFIGURED");

  const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      audience: `https://${AUTH0_DOMAIN}/api/v2/`,
    }),
  });
  if (!response.ok) throw new Error("AUTH0_MANAGEMENT_AUTH_FAILED");
  const result = await response.json();
  if (typeof result.access_token !== "string" || typeof result.expires_in !== "number") {
    throw new Error("AUTH0_MANAGEMENT_AUTH_FAILED");
  }
  tokenCache = { value: result.access_token, expiresAt: Date.now() + result.expires_in * 1000 };
  return tokenCache.value;
}

async function managementRequest(method: string, path: string, body?: Record<string, unknown>) {
  const token = await getManagementToken();
  const response = await fetch(`https://${AUTH0_DOMAIN}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const raw = await response.text();
  let result: any = null;
  try {
    result = raw ? JSON.parse(raw) : null;
  } catch {
    result = null;
  }
  if (!response.ok) {
    const error = new Error(`AUTH0_API_${response.status}`);
    (error as any).status = response.status;
    throw error;
  }
  return result;
}

function isSigaConnectionUser(user: any) {
  return Array.isArray(user?.identities)
    && user.identities.some((identity: any) => identity?.connection === AUTH0_CONNECTION_NAME);
}

async function listAuth0Users() {
  const users: any[] = [];
  let total = Number.POSITIVE_INFINITY;
  for (let page = 0; page < 100; page += 1) {
    const params = new URLSearchParams({
      search_engine: "v3",
      q: `identities.connection:"${AUTH0_CONNECTION_NAME.replaceAll('"', "")}"`,
      per_page: "100",
      page: String(page),
      include_totals: "true",
    });
    const result = await managementRequest("GET", `/api/v2/users?${params.toString()}`);
    const batch = Array.isArray(result?.users) ? result.users : [];
    users.push(...batch.filter(isSigaConnectionUser));
    total = typeof result?.total === "number" ? result.total : total;
    if (batch.length < 100 || users.length >= total) return users;
  }
  throw new Error("AUTH0_USER_LIST_LIMIT");
}

function safeUser(user: any, identity?: any) {
  return {
    id: user.user_id,
    siga_user_id: identity?.id ?? null,
    email: user.email ?? "",
    full_name: user.user_metadata?.full_name ?? user.name ?? "",
    role: identity?.role ?? roleFrom(user.app_metadata?.siga_role),
    created_at: user.created_at ?? null,
    email_confirmed_at: user.email_verified ? user.updated_at ?? null : null,
  };
}

async function requireAdministrator(req: Request) {
  const { data: context, error } = await createSupabaseContext(req, { auth: "user" });
  if (error || !context) return { error: respond({ error: "Sessão inválida. Entre novamente no SIGA." }, 401) };

  const claims = (context.jwtClaims ?? {}) as Record<string, unknown>;
  if (!isTrustedAuth0Claims(claims) || claims.email_verified !== true) {
    return { error: respond({ error: "A sessão não pertence a uma conta SIGA confirmada." }, 401) };
  }
  const identity = await findSigaIdentity(context.supabaseAdmin, String(claims.sub));
  if (!identity || identity.role !== "admin") {
    return { error: respond({ error: "Somente administradores podem gerenciar contas e permissões." }, 403) };
  }
  return { context, actor: identity };
}

async function listIdentityMap(admin: any, users: any[]) {
  const subjects = users.map((user) => user.user_id).filter((value) => typeof value === "string");
  if (!subjects.length) return new Map<string, any>();
  const { data, error } = await admin
    .from("siga_user_identities")
    .select("id,auth0_sub,email,full_name,role")
    .in("auth0_sub", subjects);
  if (error) throw error;
  return new Map((data ?? []).map((identity: any) => [identity.auth0_sub, identity]));
}

async function ensureEmailAvailable(admin: any, email: string, auth0Sub?: string) {
  const { data, error } = await admin
    .from("siga_user_identities")
    .select("id,auth0_sub")
    .eq("email_key", normalizeEmail(email))
    .limit(3);
  if (error) throw error;
  const rows = data ?? [];
  if (rows.length > 1 || rows.some((row: any) => row.auth0_sub && row.auth0_sub !== auth0Sub)) {
    throw new SigaIdentityError("Este e-mail já está associado a outra conta SIGA.", 409);
  }
}

async function createUser(admin: any, body: Record<string, unknown>) {
  const fullName = String(body.fullName ?? "").trim();
  const email = normalizeEmail(String(body.email ?? ""));
  const password = String(body.password ?? "");
  const role = roleFrom(body.role);
  if (!fullName || fullName.length > 180) return respond({ error: "Informe um nome válido." }, 400);
  if (!isValidEmail(email) || email.length > 254) return respond({ error: "Informe um e-mail válido." }, 400);
  if (password.length < 8 || password.length > 128) return respond({ error: "A senha inicial precisa ter entre 8 e 128 caracteres." }, 400);

  await ensureEmailAvailable(admin, email);
  let created: any;
  try {
    created = await managementRequest("POST", "/api/v2/users", {
      connection: AUTH0_CONNECTION_NAME,
      email,
      password,
      email_verified: true,
      user_metadata: { full_name: fullName },
      app_metadata: { siga_role: role },
    });
  } catch (error) {
    console.error("SIGA Auth0 user creation failed:", (error as any)?.status ?? "network");
    const status = (error as any)?.status;
    if (status === 409 || status === 400) return respond({ error: "Não foi possível cadastrar a conta. Confira se o e-mail já existe e se a senha atende aos requisitos do Auth0." }, 400);
    throw error;
  }
  if (typeof created?.user_id !== "string") throw new Error("AUTH0_USER_CREATE_INVALID_RESPONSE");

  try {
    const identity = await ensureSigaIdentity(admin, {
      sub: created.user_id,
      email,
      fullName,
    }, { role, updateRole: true, overwriteProfile: true });
    return respond({ user: safeUser(created, identity) }, 201);
  } catch (error) {
    try {
      await managementRequest("DELETE", `/api/v2/users/${encodeURIComponent(created.user_id)}`);
    } catch (rollbackError) {
      console.error("SIGA Auth0 rollback failed:", rollbackError);
    }
    throw error;
  }
}

async function updateUser(admin: any, body: Record<string, unknown>, actor: any) {
  const userId = String(body.userId ?? "");
  const fullName = String(body.fullName ?? "").trim();
  const email = normalizeEmail(String(body.email ?? ""));
  const password = typeof body.password === "string" ? body.password : "";
  const role = roleFrom(body.role);
  if (!userId || userId.length > 255 || userId.includes("/") || userId.includes("\\")) return respond({ error: "Conta inválida." }, 400);
  if (!fullName || fullName.length > 180) return respond({ error: "Informe um nome válido." }, 400);
  if (!isValidEmail(email) || email.length > 254) return respond({ error: "Informe um e-mail válido." }, 400);
  if (password && (password.length < 8 || password.length > 128)) return respond({ error: "A nova senha precisa ter entre 8 e 128 caracteres." }, 400);

  let current: any;
  try {
    current = await managementRequest("GET", `/api/v2/users/${encodeURIComponent(userId)}`);
  } catch (error) {
    if ((error as any)?.status === 404) return respond({ error: "Conta não encontrada." }, 404);
    throw error;
  }
  if (!isSigaConnectionUser(current)) return respond({ error: "Conta não encontrada na conexão de usuários do SIGA." }, 404);

  const currentIdentity = await findSigaIdentity(admin, userId);
  const currentRole = currentIdentity?.role ?? roleFrom(current.app_metadata?.siga_role);
  if (userId === actor.auth0_sub && role !== "admin") {
    return respond({ error: "Não é permitido remover o próprio perfil de administrador." }, 400);
  }
  if (currentRole === "admin" && role !== "admin") {
    const { count, error } = await admin
      .from("siga_user_identities")
      .select("id", { count: "exact", head: true })
      .eq("role", "admin");
    if (error) throw error;
    if ((count ?? 0) <= 1) return respond({ error: "Mantenha pelo menos um administrador ativo." }, 400);
  }

  await ensureEmailAvailable(admin, email, userId);
  const update: Record<string, unknown> = {
    email,
    email_verified: true,
    user_metadata: { ...(current.user_metadata ?? {}), full_name: fullName },
    app_metadata: { ...(current.app_metadata ?? {}), siga_role: role },
  };
  if (password) update.password = password;
  const updated = await managementRequest("PATCH", `/api/v2/users/${encodeURIComponent(userId)}`, update);
  const identity = await ensureSigaIdentity(admin, {
    sub: updated.user_id,
    email,
    fullName,
  }, { role, updateRole: true, overwriteProfile: true });
  return respond({ user: safeUser(updated, identity) });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "Método não permitido." }, 405);

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid body");
    body = parsed as Record<string, unknown>;
  } catch {
    return respond({ error: "Requisição inválida." }, 400);
  }

  try {
    const required = await requireAdministrator(req);
    if (required.error) return required.error;
    const { context, actor } = required;
    const admin = context.supabaseAdmin;
    const action = String(body.action ?? "");

    if (action === "list_users") {
      const users = await listAuth0Users();
      const identityMap = await listIdentityMap(admin, users);
      return respond({ users: users.map((user) => safeUser(user, identityMap.get(user.user_id))) });
    }

    if (action === "create_user") return await createUser(admin, body);
    if (action === "update_user") return await updateUser(admin, body, actor);

    if (action === "list_assignments") {
      const { data, error } = await admin
        .from("siga_user_unit_permissions")
        .select("user_id,unit_id,permissions,granted_at")
        .order("granted_at", { ascending: false });
      if (error) throw error;
      return respond({ assignments: data ?? [] });
    }

    if (action === "grant_unit_access") {
      const userId = String(body.userId ?? "");
      const unitId = String(body.unitId ?? "");
      if (!isValidUUID(userId) || !isValidUUID(unitId)) {
        return respond({ error: "Selecione um usuário e uma unidade válidos." }, 400);
      }
      const { data: target, error: targetError } = await admin
        .from("siga_user_identities")
        .select("id,role")
        .eq("id", userId)
        .maybeSingle();
      if (targetError || !target) return respond({ error: "Usuário não encontrado." }, 404);
      if (target.role === "admin") return respond({ error: "Administradores já têm acesso a todas as unidades." }, 400);

      const { data: unit, error: unitError } = await admin
        .from("siga_units")
        .select("id,is_active")
        .eq("id", unitId)
        .maybeSingle();
      if (unitError || !unit) return respond({ error: "Unidade não encontrada." }, 404);
      if (!unit.is_active) return respond({ error: "Ative a unidade antes de vinculá-la." }, 400);

      const now = new Date().toISOString();
      const { error } = await admin.from("siga_user_unit_permissions").upsert({
        user_id: userId,
        unit_id: unitId,
        permissions: { "units.read": true },
        granted_by: actor.id,
        granted_at: now,
        updated_at: now,
      });
      if (error) throw error;
      return respond({ ok: true });
    }

    if (action === "revoke_unit_access") {
      const userId = String(body.userId ?? "");
      const unitId = String(body.unitId ?? "");
      if (!isValidUUID(userId) || !isValidUUID(unitId)) return respond({ error: "Vínculo inválido." }, 400);
      const { error } = await admin
        .from("siga_user_unit_permissions")
        .delete()
        .eq("user_id", userId)
        .eq("unit_id", unitId);
      if (error) throw error;
      return respond({ ok: true });
    }

    return respond({ error: "Ação administrativa desconhecida." }, 400);
  } catch (error) {
    console.error("siga-admin-users:", error);
    if (error instanceof SigaIdentityError) return respond({ error: error.message }, error.status);
    if ((error as any)?.message === "AUTH0_MANAGEMENT_NOT_CONFIGURED") {
      return respond({ error: "A configuração administrativa do Auth0 ainda não foi concluída." }, 503);
    }
    return respond({ error: "Não foi possível concluir a operação. Confira a conexão e tente novamente." }, 500);
  }
});
