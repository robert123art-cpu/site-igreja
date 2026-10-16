CREATE INDEX IF NOT EXISTS siga_units_created_by_idx
  ON public.siga_units (created_by)
  WHERE created_by IS NOT NULL;

CREATE INDEX IF NOT EXISTS siga_units_updated_by_idx
  ON public.siga_units (updated_by)
  WHERE updated_by IS NOT NULL;

CREATE INDEX IF NOT EXISTS siga_user_unit_permissions_granted_by_idx
  ON public.siga_user_unit_permissions (granted_by)
  WHERE granted_by IS NOT NULL;
