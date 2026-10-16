UPDATE public.siga_units
SET code = 'JP-01-0001AD', updated_at = now()
WHERE unit_type = 'Administração'
  AND name = 'Administração Central'
  AND (code IS NULL OR btrim(code) = '');
