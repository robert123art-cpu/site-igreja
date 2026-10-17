# SIGA: integração com Auth0

## Estado desta branch

O código, a migração e as instruções estão preparados em `auth0-siga-auth`. Eles ainda não foram publicados no site nem aplicados ao Supabase de produção. A mudança da página de login só deve ser publicada depois que o Auth0 e as duas Edge Functions estiverem prontos.

A configuração registrada no tenant de desenvolvimento usa:

- Domínio: `dev-bggmfdxl7xrd7z2c.us.auth0.com`
- Tenant ID: `dev-bggmfdxl7xrd7z2c`
- Aplicativo SPA: `SIGA`
- Callback e logout: `https://robert123art-cpu.github.io/site-igreja/siga/`
- Origem web: `https://robert123art-cpu.github.io`
- Conexão de banco de dados: `Username-Password-Authentication`

O cadastro público dessa conexão foi desativado. Não há alterações de SMTP nesta implementação.

## Auth0

1. Confirme que a conexão `Username-Password-Authentication` está habilitada para o aplicativo SPA `SIGA` e que **Disable Sign Ups** continua ativado.
2. Crie uma Action Post Login com o conteúdo de [post-login-action.js](../siga/auth0/post-login-action.js), publique-a e inclua-a no fluxo **Login**.
3. Crie um aplicativo Machine to Machine para o SIGA e autorize-o na API **Auth0 Management API**. Conceda:
   - `read:users`
   - `create:users`
   - `update:users`
   - `delete:users` (usado apenas para desfazer uma criação se o vínculo SIGA falhar)
   - `read:users_app_metadata`
   - `update:users_app_metadata`
4. Para desativar também a recuperação/troca de senha pelo usuário, use um token administrativo com `read:connections` e `update:connections`. Consulte a conexão atual primeiro, preserve todas as opções existentes e defina `options.disable_self_service_change_password` como `true`. Essa opção é uma configuração da conexão e não exige mudança de SMTP.
5. Guarde o Client ID e o Client Secret do aplicativo Machine to Machine no gerenciador de segredos do Supabase. Não os coloque no repositório nem no navegador.

## Supabase

1. Em **Authentication → Sign In / Providers → Third-Party Auth**, adicione o Auth0 com tenant `dev-bggmfdxl7xrd7z2c` e região `us`, se solicitada. O emissor usado nas políticas é `https://dev-bggmfdxl7xrd7z2c.us.auth0.com/`.
2. Configure estes segredos para as Edge Functions:
   - `AUTH0_DOMAIN` = `dev-bggmfdxl7xrd7z2c.us.auth0.com`
   - `AUTH0_CONNECTION_NAME` = `Username-Password-Authentication`
   - `AUTH0_M2M_CLIENT_ID` = Client ID do aplicativo Machine to Machine
   - `AUTH0_M2M_CLIENT_SECRET` = Client Secret do aplicativo Machine to Machine
3. Aplique a migração `supabase/migrations/20261017011803_siga_auth0_identity.sql`.
4. Implante `siga-resolve-identity` e `siga-admin-users`. A configuração mantém `verify_jwt = true).
5. Só depois publique esta branch no site.

A migração conserva os UUIDs existentes do Supabase e cria o vínculo Auth0 → UUID interno por e-mail confirmado. As permissões de unidade continuam apontando para o UUID interno; as policies validam o emissor Auth0 e consultam o vínculo privado no banco. A tabela de identidades não fica acessível diretamente pelo navegador.

A tabela `siga_members` ainda não tem coluna de unidade. Por isso, a migração restringe essa tabela aos administradores até que os registros possam receber um vínculo de unidade seguro.

## Contas e senhas

O administrador cria e atualiza contas pelo SIGA. A senha é enviada diretamente do navegador para a Edge Function autenticada e, dali, para o Management API do Auth0; ela não é armazenada pelo SIGA. O usuário não recebe cadastro público nem fluxo próprio de alteração de senha. A senha inicial e as redefinições devem ser entregues pelo administrador por um canal seguro.

## Antes da publicação

Confirme a configuração de Third-Party Auth e o possível impacto de cobrança do uso de autenticação de terceiros no plano atual do Supabase. Teste o acesso de administrador, uma conta sem acesso de unidade e uma conta vinculada a uma unidade antes de liberar a branch aos usuários.
