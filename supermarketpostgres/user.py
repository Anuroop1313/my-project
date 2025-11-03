import psycopg2
import getpass
import tabulate
from psycopg2 import sql

try:
    conn = psycopg2.connect(
        dbname="selfsupermarket",
        user="postgres",
        password="2005",
        host="localhost"
    )
    
    curs = conn.cursor()
except Exception as e:
    print(f"Error connecting to PostgreSQL: {e}")
    
    exit()


curs.execute("""
CREATE TABLE IF NOT EXISTS "user"(
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL 
    ) 
""")


curs.execute("""
CREATE TABLE IF NOT EXISTS products(
    pro_id SERIAL PRIMARY KEY,
    pro_name VARCHAR(255) NOT NULL,
    category VARCHAR(255),
    price NUMERIC(10, 2) NOT NULL,
    qty INTEGER NOT NULL
)""")


curs.execute("""
CREATE TABLE IF NOT EXISTS purchases(
    purchase_id SERIAL PRIMARY KEY,
    pro_id INTEGER NOT NULL,
    qty INTEGER NOT NULL,
    timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    FOREIGN KEY(pro_id) REFERENCES products(pro_id)
)""")
conn.commit()


cart = {}

def register():
    username = input("Enter a username: ")
    password = getpass.getpass("Enter a password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    try:
       
        curs.execute("INSERT INTO \"user\" (username, password) VALUES (%s, %s)", (username, password))
        conn.commit()
        print(" User registered successfully!")
    except psycopg2.errors.UniqueViolation:
        
        conn.rollback() 
        print(" Username already exists. Please try another.")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred: {e}")

def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    
    curs.execute("SELECT * FROM \"user\" WHERE username=%s AND password=%s", (username, password))
    user = curs.fetchone()

    if user:
        print(f" Login successful! Welcome, {username}.")
        user_menu() 
    else:
        print(" Invalid username or password.")

def view_inventorys():
    print("-----VIEW OPTIONS-----")
    print("1. View all inventory")
    print("2. View by category")
    print("3. View by price range")
    choice=input("Enter the choice(1-3):")
    
    
    base_query = "SELECT pro_id, pro_name, category, price, qty FROM products"
    headers = ["pro_id", "pro_name", "category", "price", "qty"]
    records = []

    if choice == "1":
        curs.execute(base_query)
        records = curs.fetchall()
    elif choice == "2":
        category = input("Enter category: ")
        curs.execute(base_query + " WHERE category = %s", (category,))
        records = curs.fetchall()
    elif choice == "3":
        try:
            min_price = float(input("Enter minimum price: "))
            max_price = float(input("Enter maximum price: "))
            curs.execute(base_query + " WHERE price BETWEEN %s AND %s", (min_price, max_price))
            records = curs.fetchall()
        except ValueError:
            print("Invalid price input.")
            return
    else:
        print("Invalid choice!!!!")
        return

    if records:
        print(tabulate.tabulate(records, headers=headers, tablefmt="pretty"))
    else:
        print("No products found matching your criteria.")

def add_to_cart():
    view_inventorys()
    try:
        pro_id = int(input("\nEnter the ID of the product you want to add: "))
        qty_to_add = int(input("Enter the quantity: "))
        
       
        curs.execute("SELECT pro_name, price, qty FROM products WHERE pro_id = %s", (pro_id,))
        record = curs.fetchone()

        if not record:
            print(f" Product with ID {pro_id} not found.")
            return

        pro_name, price, available_qty = record
        
        if qty_to_add <= 0:
            print(" Quantity must be a positive number.")
            return

        if qty_to_add > available_qty:
            print(f" Not enough stock available. Only {available_qty} left.")
            return
        
        
        price_float = float(price)

        if pro_id in cart:
            cart[pro_id]['qty'] += qty_to_add
            print(f" Added {qty_to_add} more of '{pro_name}' to your cart.")
        else:
            cart[pro_id] = {'name': pro_name, 'price': price_float, 'qty': qty_to_add}
            print(f" Added {qty_to_add} of '{pro_name}' to your cart.")
    
    except ValueError:
        print(" Invalid input. Please enter a number for product ID and quantity.")

def view_cart():
    if not cart:
        print("Your cart is empty.")
        return

    table_data = []
    total_price = 0
    for pro_id, item in cart.items():
        subtotal = item['qty'] * item['price']
        total_price += subtotal
        table_data.append([pro_id, item['name'], item['qty'], f"${item['price']:.2f}", f"${subtotal:.2f}"])

    print("\n ADD TO CART ")
    print(tabulate.tabulate(table_data, headers=["ID", "Product", "Quantity", "Price/Unit", "Subtotal"], tablefmt="pretty"))
    print(f"\nTOTAL: ${total_price:.2f} ")

def remove_from_cart():
    """Allows the user to remove a product from their cart."""
    if not cart:
        print("Your cart is empty. Nothing to remove.")
        return

    view_cart()

    try:
        pro_id = int(input("\nEnter the ID of the product to remove: "))
        
        if pro_id not in cart:
            print(f"Product with ID {pro_id} is not in your cart.")
            return

        qty_input = input("Enter the quantity to remove (press Enter to remove all): ")
        qty_to_remove = int(qty_input) if qty_input else cart[pro_id]['qty']

        if qty_to_remove <= 0:
            print("Quantity must be a positive number.")
            return
        
        if qty_to_remove >= cart[pro_id]['qty']:
            
            item_name = cart[pro_id]['name']
            del cart[pro_id]
            print(f"All units of '{item_name}' have been removed from your cart.")
        else:
           
            cart[pro_id]['qty'] -= qty_to_remove
            item_name = cart[pro_id]['name']
            print(f"{qty_to_remove} units of '{item_name}' have been removed from your cart.")
    except ValueError:
        print("Invalid input. Please enter a number.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def view_trending_products():
    """Displays the top 5 most purchased products from the last two weeks."""
    print("\n--- TRENDING PRODUCTS (LAST 7 DAYS) ---")
    
    
    curs.execute("""
        SELECT p.pro_name, p.category, SUM(pc.qty) as total_sold
        FROM products p
        JOIN purchases pc ON p.pro_id = pc.pro_id
        WHERE pc.timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY p.pro_id, p.pro_name, p.category
        ORDER BY total_sold DESC
        LIMIT 5
    """)
    records = curs.fetchall()

    if records:
        print(tabulate.tabulate(records, headers=["Product", "Category", "Total Sold"], tablefmt="pretty"))
    else:
        print("No purchase data available in the last 7 days. Start shopping to see what's trending!")

def checkout():
    if not cart:
        print(" Your cart is empty. Nothing to checkout.")
        return
    
    view_cart()
    confirm = input("Confirm purchase? (yes/no): ").lower()
    if confirm != 'yes':
        print("Checkout cancelled.")
        return

    try:
        
        for pro_id, item in cart.items():
            qty_purchased = item['qty']
            
            # 1. Update product stock (inventory)
            curs.execute("UPDATE products SET qty = qty - %s WHERE pro_id = %s", (qty_purchased, pro_id))
            
            # 2. Log the purchase in the purchases table
            curs.execute("INSERT INTO purchases (pro_id, qty) VALUES (%s, %s)", (pro_id, qty_purchased))
        
        conn.commit() # Commit the transaction if all updates and inserts were successful
        print("\nCheckout successful! Thank you for your purchase.")
        cart.clear()

    except Exception as e:
        conn.rollback() # Rollback all changes if any step failed
        print(f"An error occurred during checkout. Purchase failed: {e}")

def main():
    while True:
        print("\nSHOP APPLICATION MENU")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Choose an option (1/2/3): ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Exiting application. Goodbye!")
            # Close the connection when exiting the application
            curs.close()
            conn.close()
            break
        else:
            print(" Invalid choice, please try again.")

def user_menu():
    while True:
        print("\n USER MENU ")
        print("1. Shop (Add items to your cart)")
        print("2. View Cart")
        print("3. Remove a Product from Cart")
        print("4. Checkout")
        print("5. View Inventory")
        print("6. View Trending Products")
        print("7. Logout")

        choice = input("Enter your choice (1-7): ")

        if choice == "1":
            add_to_cart()
        elif choice == "2":
            view_cart()
        elif choice == "3":
            remove_from_cart()
        elif choice == "4":
            checkout()
        elif choice == "5":
            view_inventorys()
        elif choice == "6":
            view_trending_products()
        elif choice == "7":
            print("Logging out.")
            break
        else:
            print(" Invalid choice. Please try again.")

if __name__ == "__main__":
    main()