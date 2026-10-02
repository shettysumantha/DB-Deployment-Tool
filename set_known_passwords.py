import psycopg2
from werkzeug.security import generate_password_hash

conn = psycopg2.connect(host='localhost', port=5432, dbname='postgres', user='postgres', password='Shetty@123')
cur = conn.cursor()
for username, password in [('bootstrapadmin', 'AdminPass123!'), ('normaluser', 'UserPass123!')]:
    hash_value = generate_password_hash(password)
    cur.execute("UPDATE app_security.users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE username = %s", (hash_value, username))
    print(username, cur.rowcount)
conn.commit()
conn.close()
