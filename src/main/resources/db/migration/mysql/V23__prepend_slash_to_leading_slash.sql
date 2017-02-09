UPDATE named_secret
  SET name = CONCAT('/', name)
  WHERE name NOT LIKE '/%';
