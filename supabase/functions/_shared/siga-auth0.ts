export const AUTH0_DOMAIN = "dev-bggmfdxl7xrd7z2c.us.auth0.com";
export const AUTH0_ISSUER = `https://${AUTH0_DOMAIN}/`;
export const SIGA_ROLE_CLAIM = "https://github.com/robert123art-cpu/site-igreja/claims/siga_role";

export type SigaRole = "admin" | "user";

export class SigaIdentityError extends Error {
  status: number;

  constructor(message: string, status = 409) {
    super(message);
    this.name = "SigaIdentityError";
    this.status = status;
  }
}

export function normalizeEmail(value: string) {
  return value.trim().toLowerCase();
}

export function isValidEmail(value: string) {
  return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(value);
}

export function isTrustedAuth0Claims(claims: Record<string, unknown>) {
  return claims.iss === AUTH0_ISSUER
    && claims.role === "authenticated"
    && typeof claims.sub === "string"
    && claims.sub.length > 0
    && claims.sub.length <= 255;
}

export async function findSigaIdentity(admin: any, auth0Sub: string) {
  const { data, error } = await admin
    .from("siga_user_identities")
    .select("id,auth0_sub,email,email_key,full_name,role")
    .eq("auth0_sub", auth0Sub)
    .maybeSingle();
  if (error) throw error;
  return data;
}

type IdentityInput = {
  sub: string;
  email: string;
  fullName?: string;
};

type EnsureIdentityOptions = {
  role?: SigaRole;
  updateRole?: boolean;
  overwriteProfile?: boolean;
};

export async function ensureSigaIdentity(
  admin: any,
  input: IdentityInput,
  options: EnsureIdentityOptions = {},
) {
  const email = normalizeEmail(input.email);
  if (!isValidEmail(email) || email.length > 254) {
    throw new SigaIdentityError("O e-mail da conta Auth0 não é válido.", 400);
  }
  const emailKey = email;
  const now = new Date().toISOString();
  const fullName = (input.fullName ?? "").trim().slice(0, 180);

  const existing = await findSigaIdentity(admin, input.sub);
  if (existing) {
    const patch: Record<string, unknown> = {
      email,
      email_key: emailKey,
      updated_at: now,
    };
    if (fullName && (options.overwriteProfile || !existing.full_name)) patch.full_name = fullName;
    if (options.updateRole && options.role) patch.role = options.role;
    const { data, error } = await admin
      .from("siga_user_identities")
      .update(patch)
      .eq("id", existing.id)
      .select("id,auth0_sub,email,full_name,role")
      .single();
    if (error) throw new SigaIdentityError("Não foi possível atualizar o vínculo da conta SIGA.", 409);
    return data;
  }

  const { data: candidates, error: lookupError } = await admin
    .from("siga_user_identities")
    .select("id,auth0_sub,email,email_key,full_name,role")
    .eq("email_key", emailKey)
    .limit(2);
  if (lookupError) throw lookupError;
  if ((candidates ?? []).length > 1) {
    throw new SigaIdentityError("Há mais de uma conta antiga com este e-mail. O administrador precisa revisar o vínculo.");
  }

  const candidate = candidates?.[0];
  if (candidate?.auth0_sub && candidate.auth0_sub !== input.sub) {
    throw new SigaIdentityError("Este e-mail já está vinculado a outra conta Auth0.");
  }

  if (candidate) {
    const patch: Record<string, unknown> = {
      auth0_sub: input.sub,
      email,
      email_key: emailKey,
      updated_at: now,
    };
    if (fullName && (options.overwriteProfile || !candidate.full_name)) patch.full_name = fullName;
    if (options.updateRole && options.role) patch.role = options.role;
    const { data, error } = await admin
      .from("siga_user_identities")
      .update(patch)
      .eq("id", candidate.id)
      .is("auth0_sub", null)
      .select("id,auth0_sub,email,full_name,role")
      .maybeSingle();
    if (error) throw new SigaIdentityError("Não foi possível associar a conta Auth0 ao cadastro SIGA.", 409);
    if (data) return data;
    const raced = await findSigaIdentity(admin, input.sub);
    if (raced) return raced;
    throw new SigaIdentityError("O vínculo da conta foi alterado por outra operação. Tente novamente.");
  }

  const { data, error } = await admin
    .from("siga_user_identities")
    .insert({
      auth0_sub: input.sub,
      email,
      email_key: emailKey,
      full_name: fullName,
      role: options.role ?? "user",
    })
    .select("id,auth0_sub,email,full_name,role")
    .single();
  if (error) {
    const raced = await findSigaIdentity(admin, input.sub);
    if (raced) return raced;
    throw new SigaIdentityError("Não foi possível criar o vínculo da conta SIGA.", 409);
  }
  return data;
}
