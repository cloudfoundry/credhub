UPDATE named_secret
  SET name = '/' || name
  WHERE name NOT LIKE '/%';
