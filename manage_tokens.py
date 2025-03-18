import argparse
import sqlite3
import secrets
import requests
import json

"""

This script is used to create and manage tokens and proxy servers.

The script uses SQLite to store the tokens and proxy servers.


"""

def init_db():
    """
    Initialize the SQLite database and create the tokens and proxy servers tables if they don't exist.

    Args:
        None
    """
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            token TEXT NOT NULL UNIQUE
        );
                   ''')

    cursor.execute('''
                   
        CREATE TABLE IF NOT EXISTS proxy_servers (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL UNIQUE
        );
    ''')
    conn.commit()
    conn.close()

def add_token(name):
    """Add a new token to the database.

    Args:
        name (str): The name associated with the token.
    """
    # check if there is at least one proxy server.
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM proxy_servers')
    if cursor.fetchone():
        print("There must be at least one proxy server. Add one with the --add-proxy-server flag.")
        return
    conn.close()



    token = generate_token()  # Generate a secure random token.
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO tokens (name, token) VALUES (?, ?)', (name, token))
        conn.commit()
        print(f"Token '{token}' added successfully with name '{name}'.")
    except sqlite3.IntegrityError:
        print("A token with this name or value already exists.")
    finally:
        conn.close()

def generate_token():
    """Generate a secure random token.

    Returns:
        str: A secure random token in hexadecimal format.
    """
    # Generates a random token of 32 hex characters.
    return secrets.token_hex(16)

def list_tokens():
    """
    List all tokens in the database.

    Args:
        None

    Returns:
        Prints the tokens to the console.
    """
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, token FROM tokens')
    tokens = cursor.fetchall()
    conn.close()

    if tokens:
        print("Current Tokens:")
        for name, token in tokens:
            print(f"Name: {name}, Token: {token}")
    else:
        print("No tokens found.")

def delete_token(name):
    """Delete a token by name from the database.

    Args:
        name (str): The name of the token to be deleted.

    Returns:
        Prints a message to the console indicating the success or failure of the operation.
    """
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM tokens WHERE name = ?', (name,))
    if cursor.rowcount > 0:
        print(f"Token with name '{name}' deleted successfully.")
    else:
        print(f"No token found with name '{name}'.")
    conn.commit()
    conn.close()

    # select the proxy servers
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM proxy_servers')
    proxy_servers = cursor.fetchall()
    conn.close()

    # Print them and add a number before each line. Based on the number, get the proxy server url.
    proxy_server_url = None
    if len(proxy_servers) > 0:
        for i, proxy_server in enumerate(proxy_servers):
            print(f"{i+1}. {proxy_server[0]}")
        selection = input("Enter the number of the proxy server to delete: ")
        try:
            selection = int(selection)
            proxy_server_url = proxy_servers[selection-1][0]
        except ValueError:
            print("Invalid selection. Please enter a valid number.")
            return
    else:
        print("No proxy servers found.")
        return

    # Call the proxy server refresh function with the selected proxy server. /refresh-tokens
    response = requests.get(f'{proxy_server_url}/refresh-tokens')

    # Convert the json response ot plain text.
    response = response.json()
    print("***", response['message'], "***")

    
def add_proxy_server(url):
    """Add a new proxy server to the database.

    Args:
        name (str): The name associated with the proxy server.
        url (str): The URL of the proxy server.

    Returns:
        Prints a message to the console indicating the success or failure of the operation.
    """
    # Check if the URL is valid.
    if not url.startswith(('http://', 'https://')):
        print("Invalid URL. It must start with http:// or https://")
        return
    # Check if the URL already exists.
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM proxy_servers WHERE url = ?', (url,))
    if cursor.fetchone():
        print("A proxy server with this URL already exists.")
        return
    # Add the proxy server to the database.
    cursor.execute('INSERT INTO proxy_servers (url) VALUES (?)', (url,))
    conn.commit()
    conn.close()

def list_proxy_servers():
    """
    List all proxy servers in the database.

    Args:
        None

    Returns:
        Prints the proxy servers to the console.
    """
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM proxy_servers')
    proxy_servers = cursor.fetchall()
    conn.close()

    if proxy_servers:
        print("Current Proxy Servers:")
        for url in proxy_servers:
            print(f"URL: {url[0]}")
    else:
        print("No proxy servers found.")

def delete_proxy_server(url):
    """Delete a proxy server by name from the database.

    Args:
        name (str): The name of the proxy server to be deleted.

    Returns:
        Prints a message to the console indicating the success or failure of the operation.
    """
    conn = sqlite3.connect('tokens.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM proxy_servers WHERE url = ?', (url,))
    if cursor.rowcount > 0:
        print(f"Proxy server with name '{url}' deleted successfully.")
    else:
        print(f"No proxy server found with name '{url}'.")
    conn.commit()
    conn.close()

def main():
    """
    Main function to handle token management.

    Args:
        None
    """
    parser = argparse.ArgumentParser(description='Token Management Script')
    parser.add_argument('--create-token', '-ct', type=str, help='Create a new token with the specified name')
    parser.add_argument('--list-tokens', '-lt', action='store_true', help='List all tokens in the database')
    parser.add_argument('--delete-token', '-dt', type=str, help='Delete a token by name')
    parser.add_argument('--add-proxy-server', '-ap', type=str, help='Add a proxy server to the database')
    parser.add_argument('--list-proxy-servers', '-lp', action='store_true', help='List all proxy servers in the database')
    parser.add_argument('--delete-proxy-server', '-dp', type=str, help='Delete a proxy server by name')

    args = parser.parse_args()

    # Initialize the database.
    init_db()

    # Handle command-line arguments.
    if args.create_token:
        add_token(args.create_token)
    elif args.list_tokens:
        list_tokens()
    elif args.delete_token:
        delete_token(args.delete_token)
    elif args.add_proxy_server:
        add_proxy_server(args.add_proxy_server)
    elif args.list_proxy_servers:
        list_proxy_servers()
    elif args.delete_proxy_server:
        delete_proxy_server(args.delete_proxy_server)
    else:
        print("No valid command provided. Use --create-token, --list-tokens, --add-proxy-server, --list-proxy-servers, or --delete-proxy-server.")

if __name__ == '__main__':
    main()
