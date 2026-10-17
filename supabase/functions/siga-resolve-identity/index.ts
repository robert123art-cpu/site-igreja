import { createSupabaseContext } from "npm:@supabase/server";
import {
  isTrustedAuth0Claims,
  isValidEmail,
  ensureSigaIdentity,
  SIGA_ROLE_CLAIM,
  type SigaRole,
  SigaIdentityError,
} from "../_shared/siga-auth0.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

function respond(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "Método não permitido." }, 405);

  const { data: context, error } = await createSupabaseContext(req, { auth: "user" });
  if (error || !context) return respond({ error: "Sessão inválida. Entre novamente no SIGA." }, 401);

  const claims = (context.jwtClaims ?? {}) as Record<string, unknown>;
  if (!isTrustedAuth0Claims(claims)) {
    return respond({ error: "A sessão não pertence ao provedor autorizado do SIGA." }, 401);
  }

  const email = typeof claims.email === "string" ? claims.email.trim() : "";
  if (claims.email_verified !== true || !isValidEmail(email)) {
    return respond({ error: "A conta precisa ter um e-mail confirmado. Fale com o administrador." }, 403);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return respond({ error: "Requisição inválida." }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return respond({ error: "Requisição inválida." }, 400);
  }

  const claimRole = claims[SIGA_ROLE_CLAIM];
  const role: SigaRole = claimRole === "admin" ? "admin" : "user";
  const fullName = typeof claims.name === "string" ? claims.name : "";

  try {
    const identity = await ensureSigaIdentity(context.supabaseAdmin, {
      sub: String(claims.sub),
      email,
      fullName,
    }, { role });
    return respond({
      user_id: identity.id,
      role: identity.role,
      email: identity.email,
      full_name: identity.full_name,
    });
  } catch (error) {
    console.error("siga-resolve-identity:", error);
    if (error instanceof SigaIdentityError) {
      return respond({ error: error.message }, error.status);
    }
    return respond({ error: "Não foi possível verificar o vínculo da conta. Fale com o administrador." }, 500);
  }
});
