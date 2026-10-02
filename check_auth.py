import psycopg2

conn = psycopg2.connect(host='localhost', port=5432, dbname='postgres', user='postgres', password='Shetty@123')
cur = conn.cursor()
cur.execute("SELECT user_id, username, email, is_admin, is_active FROM app_security.users ORDER BY user_id")
print('USERS', cur.fetchall())
cur.execute("SELECT role_id, role_name FROM app_security.roles ORDER BY role_id")
print('ROLES', cur.fetchall())
cur.execute("SELECT ur.user_id, r.role_name FROM app_security.user_roles ur JOIN app_security.roles r ON r.role_id = ur.role_id ORDER BY ur.user_id, r.role_name")
print('USER_ROLES', cur.fetchall())
cur.execute("SELECT username, password_hash FROM app_security.users WHERE username = 'bootstrapadmin'")
print('BOOTSTRAPADMIN_HASH', cur.fetchone())
conn.close()
