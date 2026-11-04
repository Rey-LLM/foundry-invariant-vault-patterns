def find(cur, uid):
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return cur.fetchone()
