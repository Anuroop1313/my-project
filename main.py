import psycopg2
import getpass
import os
import bcrypt 
import sys

# --- 1. POSTGRES CONNECTION SETUP ---

DBNAME = os.getenv("PG_DBNAME", "selfsupermarket")
USER = os.getenv("PG_USER", "postgres")
HOST = os.getenv("PG_HOST", "localhost")
PASSWORD = os.getenv("PG_PASSWORD")

if not PASSWORD:
    print(f"No PG_PASSWORD environment variable found.")
    PASSWORD = getpass.getpass(f"Enter password for PostgreSQL user '{USER}': ")

try:
    conn = psycopg2.connect(
        dbname=DBNAME,
        user=USER,
        password=PASSWORD,
        host=HOST
    )
    
    curs = conn.cursor()
    print("PostgreSQL connection successful! ✅")
except Exception as e:
    print(f"Error connecting to PostgreSQL. Please check your credentials: {e}")
    sys.exit(1)


# --- 2. TABLE CREATION (Schema Fix Included) ---

# !!! IMPORTANT FIX !!!
# This line drops the old 'admins' table structure to fix the "column not found" error.
# 🚨 DELETE THIS LINE AFTER YOU RUN THE SCRIPT ONCE AND REGISTER AN ADMIN!

# ---------------------

curs.execute("""CREATE TABLE IF NOT EXISTS admins(
    admin_id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(60) NOT NULL 
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
    print("\n--- Admin Registration ---")
    while True:
        username = input("Enter your username: ").strip()
        if username:
            break
        print("Username cannot be empty.")
        
    password = getpass.getpass("Enter your password: ")
    confirm_password = getpass.getpass("Confirm your password: ")

    if password != confirm_password:
        print("Passwords do not match. Registration failed.")
        return
        
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return

    # Secure: Hash the password before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        curs.execute("INSERT INTO admins(username, password_hash) VALUES(%s, %s)", (username, hashed_password.decode('utf-8')))
        conn.commit()
        print("Registered successfully! You can now log in. 🎉")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        print("Username already taken!")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred during registration: {e}")


def login():
    print("\n--- Admin Login ---")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    
    curs.execute("SELECT password_hash FROM admins WHERE username=%s", (username,))
    outcome = curs.fetchone()
    
    if outcome:
        stored_hash = outcome[0].encode('utf-8')
        
        # Secure: Compare the input password against the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            print("Logged in!")
            return username 
        else:
            print("Invalid details")
            return None
    else:
        print("Invalid details")
        return None



def get_valid_numeric_input(prompt, value_type):
    """Utility function to handle repeated attempts for valid numeric input."""
    while True:
        try:
            value = value_type(input(prompt))
            if value <= 0:
                print("Value must be positive.")
                continue
            return value
        except ValueError:
            print(f"Invalid input. Please enter a valid number.")

def get_valid_integer_input(prompt):
    """Utility function to handle repeated attempts for valid integer input."""
    while True:
        try:
            value = int(input(prompt))
            if value < 0:
                print("Quantity cannot be negative.")
                continue
            return value
        except ValueError:
            print(f"Invalid input. Please enter a valid whole number.")

def add_product():
    print("\n--- Add Product ---")
    
    name = input("Product name: ").strip()
    category = input("Category: ").strip()
    
    if not name or not category:
        print("Product name and category cannot be empty. Product not added.")
        return
        
    price = get_valid_numeric_input("Price: ", float)
    qty = get_valid_integer_input("Quantity: ")
        
    net_price = price * qty
    
    try:
        curs.execute("INSERT INTO products(pro_name, category, price, qty, net_price) VALUES(%s, %s, %s, %s, %s)", 
                     (name, category, price, qty, net_price))
        conn.commit()
        print("Product added successfully! 📦")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred: {e}")


def view_products():
    curs.execute("SELECT pro_id, pro_name, category, price, qty, net_price FROM products ORDER BY pro_id")
    products = curs.fetchall()

    if not products:
        print("No products found.")
        return

    
    header = ["ID", "Name", "Category", "Price (₹)", "Qty", "Net Price (₹)"]
    print("\n{:<5} {:<20} {:<15} {:<15} {:<10} {:<15}".format(*header))
    print("-" * 85)
    for p in products:
    
        price_f = float(p[3])
        net_price_f = float(p[5])
        print("{:<5} {:<20} {:<15} {:<15.2f} {:<10} {:<15.2f}".format(p[0], p[1], p[2], price_f, p[4], net_price_f))


def update_product():
    print("\n--- Update Product ---")
    try:
        pro_id = int(input("Enter Product ID to update: "))
    except ValueError:
        print("Invalid ID entered.")
        return
        
    curs.execute("SELECT * FROM products WHERE pro_id=%s", (pro_id,))
    product = curs.fetchone()
    
    if not product:
        print("Product not found.")
        return

    
    current_name = product[1]
    current_category = product[2]
    current_price = float(product[3])
    current_qty = int(product[4])

    print("\nLeave blank if you don't want to update a field.")
    
    name_input = input(f"New name [{current_name}]: ").strip()
    name = name_input if name_input else current_name
    
    category_input = input(f"New category [{current_category}]: ").strip()
    category = category_input if category_input else current_category
    
    
    price = current_price
    price_input = input(f"New price [{current_price:.2f}]: ").strip()
    if price_input:
        try:
            new_price = float(price_input)
            if new_price <= 0:
                print("Price must be positive. Update cancelled.")
                return
            price = new_price
        except ValueError:
            print("Invalid input for Price. Update cancelled.")
            return

    qty = current_qty
    qty_input = input(f"New quantity [{current_qty}]: ").strip()
    if qty_input:
        try:
            new_qty = int(qty_input)
            if new_qty < 0:
                print("Quantity cannot be negative. Update cancelled.")
                return
            qty = new_qty
        except ValueError:
            print("Invalid input for Quantity. Update cancelled.")
            return
    
    net_price = qty * price

    try:
        curs.execute("""UPDATE products SET pro_name=%s, category=%s, price=%s, qty=%s, net_price = %s 
                      WHERE pro_id=%s""", (name, category, price, qty, net_price, pro_id))
        conn.commit()
        print("Product updated successfully! ✏️")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred: {e}")

def delete_product():
    while True: 
        print("\n--- Product Deletion Menu ---")
        print("1. Delete a Single Product")
        print("2. Delete a Category")
        print("3. Exit to Product Menu")
        
        user_choice = input("Enter your choice(1, 2, or 3): ").strip()
        
        if user_choice == '1':
            try:
                pro_id = int(input("Enter Product ID to delete: "))
            except ValueError:
                print("Invalid ID entered.")
                continue

            curs.execute("SELECT pro_name FROM products WHERE pro_id=%s", (pro_id,))
            product = curs.fetchone()
            
            if product:
                confirm = input(f"Are you sure you want to delete '{product[0]}'? (yes/no): ").lower().strip()
                if confirm == 'yes':
                    try:
                        curs.execute("DELETE FROM products WHERE pro_id=%s", (pro_id,))
                        conn.commit()
                        print("Product deleted successfully! 🗑️")
                    except Exception as e:
                        conn.rollback()
                        print(f"An error occurred during deletion: {e}")
                else:
                    print("Deletion cancelled.")
            else:
                print("Product not found.")

        elif user_choice == '2':
            category_name = input("Enter the Category you want to delete: ").strip()
            
            if not category_name:
                print("Category name cannot be empty.")
                continue

            curs.execute("SELECT COUNT(*) FROM products WHERE category = %s", (category_name,))
            count = curs.fetchone()[0]

            if count > 0:
                confirm = input(f"Are you sure you want to delete ALL {count} products in '{category_name}'? (yes/no): ").lower().strip()
                if confirm == 'yes':
                    try:
                        curs.execute("DELETE FROM products WHERE category = %s", (category_name,))
                        conn.commit()
                        print(f"Successfully deleted {count} products from category: {category_name}. 🗑️")
                    except Exception as e:
                        conn.rollback()
                        print(f"An error occurred during deletion: {e}")
                else:
                    print("Deletion cancelled.")
            else:
                print(f"No products found in category: {category_name}.")

        elif user_choice == '3':
            print("Exiting Deletion Menu.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
            


def product_menu(user_id):
    while True:
        print(f"\nWelcome {user_id}! Product Management Menu:")
        print("1. Add Product\n2. View products \n3. Update Product\n4. Delete Product\n5. Logout")
        choice = input("Enter your choice: ").strip()

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
        print("\n--- ShopKeeper Management System ---")
        print("1. Register Admin \n2. Admin Login \n3. Exit")
        user_choice = input("Enter your choice: ").strip()
        
        if user_choice == '1':
            register()
        elif user_choice == '2':
            user_id = login()
            if user_id:
                product_menu(user_id)
        elif user_choice == '3':
            print("Exiting application. Goodbye! 👋")
            
            if curs and conn:
                curs.close()
                conn.close()
            break
        else: 
            print("Invalid choice.")

if __name__ == "__main__":
    main()