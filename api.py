import datetime
import json
import os
import time
import sqlite3

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


DATABASE_PATH = f"{os.path.dirname(os.path.realpath(__file__))}{os.sep}database.db"


"""
Used to process SQL requests more easily
"""
class SQL:
    """
    Convert any string to a SQL-safe string (mainly used to avoid SQL injections)
    """
    def secure(s: str):
        return s.replace("'", "''")

    """
    Constructor for the SQL class
    """
    def __init__(self):
        self.__con = sqlite3.connect(DATABASE_PATH)
        self.__cur = self.__con.cursor()

    """
    Execute a query. The results are given in a 2D list, first for each line, then for each column (res[line][col])
    """
    def query(self, request: str):
        res = self.__cur.execute(request)  # /!\ It's possible to execute SQL injections /!\
        self.__con.commit()

        # If the request wasn't supposed to return anything from the start (INSERT for example)
        if res is None:
            return None
        
        # If the request was expecting a result
        return res.fetchall()


"""
Used to process URLs more easily
"""
class URL:
    """
    Constructor for the URL class
    """
    def __init__(self, url: str):
        split = url.split("?", 1)

        # Parse the path
        self.__path = []
        for e in split[0][1:].split("/"):  # The [1:] avoid taking into account the "/" at the start if every path (leading to only empty paths, or requiring additionals processings)
            if e != "":
                self.__path.append(e)
        
        # Parse the args
        self.__args = {}
        if (len(split)) > 1:
            for e in split[1].split("&"):
                arg = e.split("=", 1)
                if len(arg) > 1:
                    self.__args[arg[0]] = arg[1]
                else:
                    self.__args[arg[0]] = True
    
    """
    Returns the Xth element of the path, or None if invalid 
    """
    def path(self, pos: int):
        if 0 < pos >= len(self.__path):
            return None
        return self.__path[pos]

    """
    Returns the specified arg, or None if invalid
    """
    def arg(self, key: str):
        if key not in self.__args.keys():
            return None
        return self.__args[key]
    

"""
A list of logged users, with an expiration time
"""
class Users:
    class __User:
        __EXPIRATION_TIME = 3600  # The delay before a token expires (in seconds)

        """
        Constructor for the User class
        """
        def __init__(self, user: Any):
            self.__user = user
            self.refresh()

        """
        Check if the user hasn't expired
        """
        def check(self):
            return time.time() < self.__expires

        """
        Return the name (or id or whatever) of an user
        """
        def get(self):
            return self.__user

        """
        Refresh the expire time of an user
        """
        def refresh(self):
            self.__expires = time.time() + self.__EXPIRATION_TIME

    """
    Constructor for the Users class
    """
    def __init__(self):
        self.__users = {}  # key = ip
    
    """
    Returns the user associated to the ip, or None if invalid. Also refreshes the user if valid
    """
    def get(self, ip: str):
        if ip not in self.__users.keys() or self.__users[ip].check() != True:
            return None
        self.__users[ip].refresh()
        return self.__users[ip].get()

    """
    If the IP isn't registered, register it. If the IP is already registered, update its associated users (meaning it will set the right username and refresh it)
    """
    def update(self, ip: str, user: Any):
        self.__users[ip] = self.__User(user)

    """
    Removes an IP
    """
    def pop(self, ip: str):
        if ip in self.__users.keys():
            self.__users.pop(ip)


SQL_INSTANCE = SQL()
USERS_INSTANCE = Users()


class Handler(BaseHTTPRequestHandler):
    """
    Instantiate self.sql and self.logged_users at the creation of the handler
    """
    def __init__(self, *args, **kwargs):
        self.sql = SQL_INSTANCE
        self.logged_users = USERS_INSTANCE
        super().__init__(*args, **kwargs)

    """
    Ovveride of the do_GET method used for GET requests
    """
    def do_GET(self):
        # Init values
        url = URL(self.path)
        http_status = HTTPStatus.NOT_FOUND
        res = None
        ip = self.client_address[0]

        # Process the path (the request)
        # Accounts-related
        if url.path(0) == "account":

            # Informations of account
            if url.path(1) is None:
                if self.logged_users.get(ip) is None:
                    http_status = HTTPStatus.FORBIDDEN  # If the client isn't logged in, forbid its access to account informations
                else:
                    if url.arg("firstname") is not None:  # Update the first name if requested
                        self.sql.query(f"""
                            UPDATE users
                            SET firstname='{SQL.secure(url.arg('firstname'))}'
                            WHERE userId={self.logged_users.get(ip)}
                        """)
                    if url.arg("lastname") is not None:  # Update the last name if requested
                        self.sql.query(f"""
                            UPDATE users
                            SET lastname='{SQL.secure(url.arg('lastname'))}'
                            WHERE userId={self.logged_users.get(ip)}
                        """)
                    if url.arg("email") is not None:  # Update the email if requested
                        self.sql.query(f"""
                            UPDATE users
                            SET email='{SQL.secure(url.arg('email'))}'
                            WHERE userId={self.logged_users.get(ip)}
                        """)
                    if url.arg("birthdate") is not None:  # Update the birth date if requested
                        self.sql.query(f"""
                            UPDATE users
                            SET birthdate='{SQL.secure(url.arg('birthdate'))}'
                            WHERE userId={self.logged_users.get(ip)}
                        """)
                    user = self.sql.query(f"""
                        SELECT firstname, lastname, email, birthdate
                        FROM users
                        WHERE userId={self.logged_users.get(ip)}
                    """)[0]
                    res = {
                        "firstname": user[0],
                        "lastname": user[1],
                        "email": user[2],
                        "birthdate": user[3]
                    }

            # Login
            elif url.path(1) == "login":
                user_id = self.sql.query(f"""
                    SELECT userId
                    FROM users
                    WHERE login='{SQL.secure(url.arg('login'))}'
                        AND password='{SQL.secure(url.arg('password'))}'
                """)
                if len(user_id) > 0:  # If there is someone matching this user & password
                    self.logged_users.update(ip, user_id[0][0])
                    res = {
                        "ok": True
                    }
                else:
                    http_status = HTTPStatus.FORBIDDEN  # If no one was found, send the correct error
                
            # Logout
            elif url.path(1) == "logout":
                self.logged_users.pop(ip)
                res = {
                    "ok": True
                }
            
            # Register
            elif url.path(1) == "register":
                user = self.sql.query(f"""
                    SELECT *
                    FROM users
                    WHERE login='{SQL.secure(url.arg('login'))}'
                """)
                if len(user) == 0:  # If no one with the specified username already exists
                    self.sql.query(f"""
                        INSERT INTO users (login, password)
                        VALUES ('{SQL.secure(url.arg('login'))}', '{SQL.secure(url.arg('password'))}')
                    """)  # Create the user
                    user_id = self.sql.query(f"""
                        SELECT userId
                        FROM users
                        WHERE login='{SQL.secure(url.arg('login'))}'
                    """)[0][0]  # Retrive the user id, to bind it to the IP
                    self.logged_users.update(ip, user_id)
                    res = {
                        "ok": True
                    }
                else:
                    http_status = HTTPStatus.FORBIDDEN  # If someone was found, send the correct error
                
        # Orders-related
        elif url.path(0) == "order":
            if self.logged_users.get(ip) is None:
                http_status = HTTPStatus.FORBIDDEN  # If the client isn't logged in, forbid its access to order-related functionnalities
            else:
                order_id = self.sql.query(f"""
                    SELECT orderId
                    FROM orders
                    WHERE userId={self.logged_users.get(ip)}
                        AND orderDate IS NULL
                """)  # Retrieve the orderId of the current user
                if len(order_id) == 0:
                    self.sql.query(f"""
                        INSERT INTO orders (userId)
                        VALUES ({self.logged_users.get(ip)}, 0)
                    """)  # If the user doesn't currently have any unfinished order, create one
                    order_id = self.sql.query(f"""
                        SELECT orderId
                        FROM orders
                        WHERE userId={self.logged_users.get(ip)}
                            AND orderDate IS NULL
                    """)  # Retrieve the orderId of the current user
                order_id = order_id[0][0]  # Convert the SQL result (list of list of values) to a real value
                
                # Get the current order
                if url.path(1) is None:
                    res = {
                        "products": []
                    }
                    for product in self.sql.query(f"""
                        SELECT productId, count
                        FROM order_lines
                        WHERE orderId={order_id}
                    """):
                        res["products"].append({
                            "id": product[0],
                            "count": product[1]
                        })

                # Add a product to the order (or update the amount if already in the order)
                elif url.path(1) == "add":
                    order_line = self.sql.query(f"""
                        SELECT productId, count
                        FROM order_lines
                        WHERE orderId={order_id}
                            AND productId={SQL.secure(url.arg('id'))}
                    """)  # Chech if there is already a line associated with this order and this product
                    if len(order_line) == 0:
                        self.sql.query(f"""
                            INSERT INTO order_lines (orderId, productId, count)
                            VALUES ({order_id}, {SQL.secure(url.arg('id'))}, {SQL.secure(url.arg('count'))})
                        """)  # If there isn't a matching line, create it
                    else:
                        self.sql.query(f"""
                            UPDATE order_lines
                            SET count={SQL.secure(url.arg('count'))}
                            WHERE orderId={order_id}
                                AND productId={SQL.secure(url.arg('id'))}
                        """)  # If there is a matching line, update the count
                    res = {
                        "ok": True
                    }
                        

                # Place the order
                elif url.path(1) == "place":
                    self.sql.query(f"""
                        UPDATE orders
                        SET orderDate='{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}'
                        WHERE userId={self.logged_users.get(ip)}
                            AND orderId={order_id}
                    """)
                    res = {
                        "ok": True
                    }
                    
                # Remove a product from the order
                elif url.path(1) == "remove":
                    self.sql.query(f"""
                        DELETE FROM order_lines
                        WHERE orderId={order_id}
                            AND productId={SQL.secure(url.arg('id'))}
                    """)
                    res = {
                        "ok": True
                    }
        
        # Products-related
        elif url.path(0) == "products":

            # Get every products
            if url.path(1) is None:
                res = {
                    "products": []
                }
                for product in self.sql.query(f"""
                    SELECT productId, productName, productPrice, productImageUrl
                    FROM products
                """):
                    res["products"].append({
                        "id": product[0],
                        "name": product[1],
                        "price": product[2],
                        "imageURL": product[3]
                    })
            
            # Get product details
            else:
                product = self.sql.query(f"""
                    SELECT productId, productName, productPrice, productImageUrl, productDescription, productCalories, productCarbohydrates, productProteins
                    FROM products
                    WHERE productId={SQL.secure(url.path(1))}
                """)
                if len(product) != 0:  # If the product exists
                    product = product[0]
                    res = {
                        "id": product[0],
                        "name": product[1],
                        "price": product[2],
                        "imageURL": product[3],
                        "description": product[4],
                        "calories": product[5],
                        "carbohydrates": product[6],
                        "proteins": product[7]
                    }

        # Send the response
        if res is None:
            self.send_response(http_status)
            self.end_headers()
        else:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
            self.wfile.flush()


if __name__ == "__main__":
    # Create the SQL table if necessary
    if not os.path.exists(DATABASE_PATH):
        SQL().query("""
            CREATE TABLE IF NOT EXISTS products(
                productId INTEGER PRIMARY KEY AUTOINCREMENT,
                 productName TEXT,
                 productPrice REAL,
                 productImageUrl TEXT,
                 productDescription TEXT,
                 productCalories INTEGER,
                 productCarbohydrates INTEGER,
                 productProteins INTEGER
            )
        """)
        SQL().query("""
            CREATE TABLE IF NOT EXISTS users(
                 userId INTEGER PRIMARY KEY AUTOINCREMENT,
                 login TEXT,
                 password TEXT,
                 firstname TEXT,
                 lastname TEXT,
                 email TEXT,
                 birthdate TEXT
            )
        """)
        SQL().query("""
            CREATE TABLE IF NOT EXISTS orders(
                orderId INTEGER PRIMARY KEY AUTOINCREMENT,
                 orderDate TEXT,
                 userId INTEGER,
                 FOREIGN KEY (userId) REFERENCES users(userId)
            )
        """)
        SQL().query("""
            CREATE TABLE IF NOT EXISTS order_lines(
                orderId INTEGER,
                 productId INTEGER,
                  count INTEGER,
                 PRIMARY KEY (orderId, productId),
                 FOREIGN KEY (orderId) REFERENCES orders(orderId),
                 FOREIGN KEY (productId) REFERENCES products(productId)
            )
        """)
        SQL().query("""
            INSERT INTO products (productName, productPrice, productImageUrl, productDescription, productCalories, productCarbohydrates, productProteins)
            VALUES ('Test', 9.99, 'test.png', 'Ceci est un produit de test. Il ne sera pas là au final.', 500, 20, 30)
        """)
        SQL().query("""
            INSERT INTO products (productName, productPrice, productImageUrl, productDescription, productCalories, productCarbohydrates, productProteins)
            VALUES ('Produit', 4.99, 'produit.png', 'Ceci est LE produit. Il ne sera malheureusement jamais proposé au public.', 1000, 10, 10)
        """)
        SQL().query("""
            INSERT INTO users (login, password, firstname, lastname, email, birthdate)
            VALUES ('root', 'root', 'Root', 'ADMIN', 'root.admin@mymail.com', '01-01-2000')
        """)
        SQL().query("""
            INSERT INTO users (login, password, firstname, lastname, email, birthdate)
            VALUES ('python', 'password', 'User', 'PYTHON', 'user.python@gmail.com', '20-02-1991')
        """)

    webServer = HTTPServer(("0.0.0.0", 8080), Handler)

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
