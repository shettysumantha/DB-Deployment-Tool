import psycopg2
from datetime import datetime
from pathlib import Path


# ==========================================
# DATABASE CONNECTION
# ==========================================

DB_CONFIG = {
    "host": "172.31.5.109",
    "port": 5432,
    "database": "mvvnl_idatum_test",
    "user": "mvvnl_idatum_user",
    "password": "yyWc5Vq8yk8z"
}

# ==========================================
# ADDITIONAL FUNCTIONS TO EXPORT
# ==========================================

EXPECTED_FUNCTIONS = [
]

# ==========================================
# OUTPUT FILE
# ==========================================

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

output_file = Path(
    f"Deploy_Functions_{timestamp}.sql"
)


# ==========================================
# GET ALL FUNCTIONS
# ==========================================

query = """
SELECT
    p.proname AS function_name,
    format('%%I.%%I', n.nspname, p.proname) AS qualified_name,
    pg_get_function_arguments(p.oid) AS function_arguments,
    pg_get_function_result(p.oid) AS function_result,
    p.prosrc AS function_body,
    l.lanname AS language_name,
    p.procost AS function_cost,
    p.prosecdef AS security_definer
FROM pg_proc p
JOIN pg_namespace n
    ON n.oid = p.pronamespace
JOIN pg_language l
    ON l.oid = p.prolang
WHERE n.nspname = 'public'
  AND p.prokind = 'f'
  AND (
        p.proname ILIKE %s
        OR p.proname = ANY(%s::text[])
      )
ORDER BY p.proname, p.oid::regprocedure::text;
"""


connection = None
cursor = None

try:
    connection = psycopg2.connect(**DB_CONFIG)
    cursor = connection.cursor()

    print("Connected to PostgreSQL")

    # Execute query
    cursor.execute(query,("%idatum%", EXPECTED_FUNCTIONS))
    
    functions = cursor.fetchall()

    print(f"Functions found: {len(functions)}")

    if not functions:
        print("No matching functions found.")
        raise SystemExit(1)

    with open(output_file, "w", encoding="utf-8", newline="") as file:

        file.write("-- ==========================================\n")
        file.write("-- AUTO GENERATED FUNCTION DEPLOYMENT SCRIPT\n")
        file.write(
            f"-- Generated : "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        file.write("-- ==========================================\n\n")

        exported_count = 0

        for row in functions:

            function_name = row[0]
            qualified_name = row[1]
            function_arguments = row[2]
            function_result = row[3]
            function_body = row[4]
            language_name = row[5]
            function_cost = row[6]
            security_definer = row[7]

            # Safety check
            if function_body is None:
                print(f"WARNING: No code found for {function_name}")
                continue

            dollar_tag = "$BODY$"
            if dollar_tag in function_body:
                dollar_tag = "$function$"

            function_code = (
                f"CREATE OR REPLACE FUNCTION {qualified_name}({function_arguments})\n"
                f" RETURNS {function_result}\n"
                f"AS {dollar_tag}\n"
                f"{function_body}"
                f"{'' if function_body.endswith(('\\r', '\\n')) else chr(10)}"
                f"{dollar_tag}\n"
                f"  LANGUAGE '{language_name}' COST {function_cost:.1f} "
                f"SECURITY {'DEFINER' if security_definer else 'INVOKER'};"
            )

            file.write("-- ==========================================\n")
            file.write(f"-- FUNCTION : {qualified_name}({function_arguments})\n")
            file.write("-- ==========================================\n\n")

            file.write(function_code)
            file.write("\n\n")

            exported_count += 1

            print(f"Added: {qualified_name}({function_arguments})")

    print("\n==========================================")
    print("SUCCESS!")
    print("==========================================")
    print(f"Functions exported: {exported_count}")
    print(f"Deployment file: {output_file.resolve()}")

except Exception as error:
    print("\nERROR:")
    print(type(error).__name__, ":", error)

finally:
    if cursor is not None:
        cursor.close()

    if connection is not None:
        connection.close()
        print("\nDatabase connection closed.")