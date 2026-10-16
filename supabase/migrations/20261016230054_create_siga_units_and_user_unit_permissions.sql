-- SIGA: cadastro dinâmico de unidades e estrutura futura de acesso por usuário/unidade.
-- Responsáveis e e-mails ficam em branco até serem informados pelo usuário.
CREATE TABLE public.siga_units (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text,
  name text NOT NULL CHECK (btrim(name) <> ''),
  japanese_name text,
  unit_type text NOT NULL CHECK (unit_type IN ('Administração', 'Departamento', 'Localidade/Igreja')),
  responsible_name text,
  responsible_email text,
  is_active boolean NOT NULL DEFAULT TRUE,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL DEFAULT auth.uid(),
  updated_by uuid REFERENCES auth.users(id) ON DELETE SET NULL DEFAULT auth.uid(),
  CONSTRAINT siga_units_type_name_key UNIQUE (unit_type, name),
  CONSTRAINT siga_units_code_nonblank CHECK (code IS NULL OR btrim(code) <> '')
);

CREATE UNIQUE INDEX siga_units_code_unique
  ON public.siga_units (upper(btrim(code)))
  WHERE code IS NOT NULL AND btrim(code) <> '';

COMMENT ON TABLE public.siga_units IS 'Cadastro dinâmico de administrações, departamentos e localidades/igrejas do SIGA.';
COMMENT ON COLUMN public.siga_units.is_active IS 'Status da unidade. Desativar preserva o cadastro e o histórico.';
COMMENT ON COLUMN public.siga_units.responsible_name IS 'Preenchido somente após confirmação do responsável pelo usuário.';

CREATE TABLE public.siga_user_unit_permissions (
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  unit_id uuid NOT NULL REFERENCES public.siga_units(id) ON DELETE CASCADE,
  permissions jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(permissions) = 'object'),
  granted_by uuid REFERENCES auth.users(id) ON DELETE SET NULL DEFAULT auth.uid(),
  granted_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, unit_id)
);

CREATE INDEX siga_user_unit_permissions_unit_id_idx
  ON public.siga_user_unit_permissions (unit_id);

COMMENT ON TABLE public.siga_user_unit_permissions IS 'Vínculo futuro Usuário → Unidade → Permissões; sem atribuições iniciais.';
COMMENT ON COLUMN public.siga_user_unit_permissions.permissions IS 'Permissões específicas do usuário dentro da unidade, representadas por chaves booleanas JSON.';

ALTER TABLE public.siga_units ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.siga_user_unit_permissions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.siga_units FROM anon;
GRANT SELECT, INSERT, UPDATE ON TABLE public.siga_units TO authenticated;
REVOKE ALL ON TABLE public.siga_user_unit_permissions FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.siga_user_unit_permissions TO authenticated;

CREATE POLICY siga_units_read_admin_or_assigned
  ON public.siga_units
  FOR SELECT TO authenticated
  USING (
    COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE)
    OR EXISTS (
      SELECT 1
      FROM public.siga_user_unit_permissions AS up
      WHERE up.unit_id = siga_units.id
        AND up.user_id = (SELECT auth.uid())
        AND up.permissions @> '{"units.read": true}'::jsonb
    )
  );

CREATE POLICY siga_units_insert_admin
  ON public.siga_units
  FOR INSERT TO authenticated
  WITH CHECK (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE));

CREATE POLICY siga_units_update_admin
  ON public.siga_units
  FOR UPDATE TO authenticated
  USING (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE))
  WITH CHECK (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE));

CREATE POLICY siga_unit_permissions_read_own_or_admin
  ON public.siga_user_unit_permissions
  FOR SELECT TO authenticated
  USING (
    user_id = (SELECT auth.uid())
    OR COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE)
  );

CREATE POLICY siga_unit_permissions_insert_admin
  ON public.siga_user_unit_permissions
  FOR INSERT TO authenticated
  WITH CHECK (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE));

CREATE POLICY siga_unit_permissions_update_admin
  ON public.siga_user_unit_permissions
  FOR UPDATE TO authenticated
  USING (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE))
  WITH CHECK (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE));

CREATE POLICY siga_unit_permissions_delete_admin
  ON public.siga_user_unit_permissions
  FOR DELETE TO authenticated
  USING (COALESCE((SELECT auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', FALSE));

INSERT INTO public.siga_units
  (code, name, japanese_name, unit_type, is_active, responsible_name, responsible_email, notes)
VALUES
  (NULL, 'Administração Central', NULL, 'Administração', TRUE, NULL, NULL, NULL),
  (NULL, 'Obra da Piedade', NULL, 'Departamento', TRUE, NULL, NULL, NULL),
  (NULL, 'Viagem', NULL, 'Departamento', TRUE, NULL, NULL, NULL),
  (NULL, 'Fundo Bíblico', NULL, 'Departamento', TRUE, NULL, NULL, NULL),
  ('JP-01-0001', 'ANJO-SHI', '安城市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0002', 'NAGOYA-SHI', '名古屋市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0003', 'TOYOHASHI-SHI', '豊橋市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0004', 'KASHIWA-SHI', '柏市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0005', 'KAKAMIGAHARA-SHI', '各務原市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0006', 'OTA-SHI', '太田市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0007', 'FUKUYAMA-SHI', '福山市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0008', 'KURE-SHI', '呉市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0009', 'TSUKUBAMIRAI', 'つくばみらい市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0010', 'AIKO-GUN', '愛甲郡', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0011', 'KAMEYAMA-SHI', '亀山市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0012', 'OKAYA-SHI', '岡谷市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0013', 'OITA-SHI', '大分市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0014', 'KURASHIKI-SHI', '倉敷市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0016', 'HIRAKATA-SHI', '枚方市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0017', 'GAMOU-GUN', '蒲生郡', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0018', 'FUJI-SHI', '富士市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0019', 'HAMAMATSU-SHI', '浜松市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0020', 'CHUO-SHI', '中央市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0021', 'YAIZU-SHI', '焼津市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0023', 'TAKAOKA-SHI', '高岡市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0024', 'NAGAHAMA-SHI', '長浜市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0025', 'SUZAKA-SHI', '須坂市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0026', 'IWATA-SHI', '磐田市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0027', 'KAKEGAWA-SHI', '掛川市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0030', 'IZUMO-SHI', '出雲市', 'Localidade/Igreja', TRUE, NULL, NULL, NULL),
  ('JP-01-0035', 'FUKUI', '福井', 'Localidade/Igreja', TRUE, NULL, NULL, NULL)
ON CONFLICT DO NOTHING;
