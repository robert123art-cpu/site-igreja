UPDATE public.siga_units AS u
SET code = v.code, updated_at = now()
FROM (VALUES
  ('Obra da Piedade', 'JP-01-0001PID'),
  ('Viagem', 'JP-01-0001VIA'),
  ('Fundo Bíblico', 'JP-01-0001FB')
) AS v(name, code)
WHERE u.unit_type = 'Departamento'
  AND u.name = v.name
  AND (u.code IS NULL OR btrim(u.code) = '');
