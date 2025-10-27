import psycopg2
import getpass
from psycopg2 import sql

# --- 1. POSTGRES CONNECTION SETUP ---
# NOTE: Update these connection details with your actual PostgreSQL credentials.
try:
    conn = psycopg2.connect(
        dbname="selfsupermarket",      # Replace with your database name
        user="postgres",       # Replace with your username
        password="2005", # Replace with your password
        host="localhost"
    )
    curs = conn.cursor()
except Exception as e:
    print(f"Error connecting to PostgreSQL. Please check your credentials and ensure the database exists: {e}")
    exit()

# --- 2. TABLE CREATION (PostgreSQL Syntax) ---
# SERIAL PRIMARY KEY replaces INTEGER PRIMARY KEY AUTOINCREMENT
# NUMERIC(10, 2) is used for monetary values (price, net_price)

curs.execute("""CREATE TABLE IF NOT EXISTS admins(
    admin_id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
    ) """
)

curs.execute("""CREATE TABLE IF NOT EXISTS products(
    pro_id SERIAL PRIMARY KEY,
    pro_name VARCHAR(255) NOT NULL,
    category VARCHAR(255) NOT NULL,
    price NUMERIC(10, 2) NOT NULL,
    qty INTEGER NOT NULL,
    net_price NUMERIC(10, 2) NOT NULL
    )"""
)

conn.commit()

# --- Admin Functions ---

def register():
    print("User Register")
    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ")

    try:
        # Use %s placeholder for psycopg2
        curs.execute("INSERT INTO admins(username,password) VALUES(%s, %s)",(username,password))
        conn.commit()
        print("Registered successfully!")
    except psycopg2.errors.UniqueViolation:
        # Catch the specific PostgreSQL error for unique constraint violation
        conn.rollback()
        print("Username already taken!")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred during registration: {e}")


def login():
    user=input("username: ").strip()
    pwd=getpass.getpass("password: ")

    # Use %s placeholder
    curs.execute("SELECT * FROM admins WHERE username=%s AND password=%s",(user,pwd))
    outcome = curs.fetchone()
    if outcome:
        print("Logged in!")
        return outcome[1] # Return the username
    else:
        print("Invalid details")
        return None

# --- Product Management Functions ---

def add_product():
    print("Add Product")
    try:
        name = input("Product name: ")
        category = input("Category: ")
        price = float(input("Price: "))
        qty = int(input("Quantity: "))
    except ValueError:
        print("Invalid input for Price or Quantity. Product not added.")
        return
        
    net_price = price * qty
    # Use %s placeholder
    curs.execute("INSERT INTO products(pro_name, category, price, qty, net_price) VALUES(%s, %s, %s, %s, %s)", (name, category, price, qty, net_price))
    conn.commit()
    print("Product added successfully!")

def view_products():
    curs.execute("SELECT pro_id, pro_name, category, price, qty, net_price FROM products ORDER BY pro_id")
    products = curs.fetchall()

    if not products:
        print("No products found.")
        return

    # Using enhanced formatting for better readability
    header = ["ID", "Name", "Category", "Price", "Qty", "Net Price"]
    print("\n{:<5} {:<20} {:<15} {:<10} {:<10} {:<15}".format(*header))
    print("-" * 80)
    for p in products:
        # NOTE: Psycopg2 returns NUMERIC types. We convert them to float for formatting.
        price_f = float(p[3])
        net_price_f = float(p[5])
        print("{:<5} {:<20} {:<15} ₹{:<9.2f} {:<10} ₹{:<13.2f}".format(p[0], p[1], p[2], price_f, p[4], net_price_f))


def update_product():
    try:
        pro_id = int(input("Enter Product ID to update: "))
    except ValueError:
        print("Invalid ID entered.")
        return
        
    # Use %s placeholder
    curs.execute("SELECT * FROM products WHERE pro_id=%s", (pro_id,))
    product = curs.fetchone()
    
    if not product:
        print("Product not found.")
        return

    # Convert NUMERIC fields to usable Python types for editing
    current_price = float(product[3])
    current_qty = int(product[4])

    print("Leave blank if you don't want to update a field.")
    name = input(f"New name [{product[1]}]: ") or product[1]
    category = input(f"New category [{product[2]}]: ") or product[2]
    
    price_input = input(f"New price [{current_price:.2f}]: ")
    qty_input = input(f"New quantity [{current_qty}]: ")
    
    # Safely convert inputs to float/int, falling back to original value
    try:
        price = float(price_input) if price_input else current_price
        qty = int(qty_input) if qty_input else current_qty
    except ValueError:
        print("Invalid input for Price or Quantity. Update cancelled.")
        return
        
    net_price = qty * price

    # Use %s placeholder
    curs.execute("""UPDATE products SET pro_name=%s, category=%s, price=%s, qty=%s, net_price = %s 
                  WHERE pro_id=%s""", (name, category, price, qty, net_price, pro_id))
    conn.commit()
    print("Product updated successfully!")

def delete_product():
    while True: 
        print("\n--- Product Deletion Menu ---")
        print("1. Delete a Single Product")
        print("2. Delete a Category")
        print("3. Exit to Product Menu")
        
        user_choice = input("Enter your choice(1, 2, or 3): ")
        
        if user_choice == '1':
            try:
                pro_id = int(input("Enter Product ID to delete: "))
            except ValueError:
                print("Invalid ID entered.")
                continue

            curs.execute("SELECT pro_name FROM products WHERE pro_id=%s", (pro_id,))
            product = curs.fetchone()
            
            if product:
                confirm = input(f"Are you sure you want to delete '{product[0]}'? (yes/no): ").lower()
                if confirm == 'yes':
                    curs.execute("DELETE FROM products WHERE pro_id=%s", (pro_id,))
                    conn.commit()
                    print("Product deleted successfully!")
                else:
                    print("Deletion cancelled.")
            else:
                print("Product not found.")

        elif user_choice == '2':
            category_name = input("Enter the Category you want to delete: ").strip()
            
            # Check if products exist before attempting deletion
            curs.execute("SELECT COUNT(*) FROM products WHERE category = %s", (category_name,))
            count = curs.fetchone()[0]

            if count > 0:
                confirm = input(f"Are you sure you want to delete ALL {count} products in '{category_name}'? (yes/no): ").lower()
                if confirm == 'yes':
                    curs.execute("DELETE FROM products WHERE category = %s", (category_name,))
                    conn.commit()
                    print(f"Successfully deleted {count} products from category: {category_name}.")
                else:
                    print("Deletion cancelled.")
            else:
                print(f"No products found in category: {category_name}.")

        elif user_choice == '3':
            print("Exiting Deletion Menu.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
            
# --- Menu Functions ---

def product_menu(user_id):
    while True:
        print(f"\nWelcome {user_id}! Product Management Menu:")
        print("1. Add Product\n2. View products \n3. Update Product\n4. Delete Product\n5. Logout")
        choice = input("Enter your choice: ")

        if choice == '1':
            add_product()
        elif choice == '2':
            view_products()
        elif choice == '3':
            update_product()
        elif choice == '4':
            delete_product()
        elif choice == '5':
            print("Logging out...\n")
            break
        else:
            print("Invalid option.")

def main():
    while True:
        print("\n--- ShopKeeper Management ---")
        print("1. Register Admin \n2. Admin Login \n3. Exit")
        user_choice = input("Enter your choice: ")
        
        if user_choice == '1':
            register()
        elif user_choice == '2':
            user_id = login()
            if user_id:
                product_menu(user_id)
        elif user_choice == '3':
            print("Exiting application. Goodbye!")
            # Close connection properly
            curs.close()
            conn.close()
            break
        else: 
            print("Invalid choice.")

if __name__ == "__main__":
    main()