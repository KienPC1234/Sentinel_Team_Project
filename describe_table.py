from django.db import connection
cursor = connection.cursor()
cursor.execute("DESCRIBE core_forumpost")
cols = cursor.fetchall()
for col in cols:
    print(col)
