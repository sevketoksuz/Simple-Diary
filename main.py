import tkinter as tk
from tkinter import Toplevel, Text, Entry, Button, Label, Listbox, Scrollbar, messagebox
import datetime
import sqlite3
import contextlib
import logging
import hashlib

# Initialize logging
logging.basicConfig(filename='diary.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Global session data
session = {"logged_in": False, "user_id": None}

# Database connection context manager
@contextlib.contextmanager
def get_db_connection():
    conn = sqlite3.connect('diary.db')
    try:
        yield conn
    except sqlite3.DatabaseError as e:
        logging.error(f"Database error: {e}")
        messagebox.showerror("Database Error", str(e))
    finally:
        conn.close()

# Initialize the database with tables for users and entries
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                title TEXT,
                content TEXT,
                date TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT
            )
        ''')
        conn.commit()

# Hash passwords for storage
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to register a new user
def register_user(username, password):
    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty.")
        return False
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone() is not None:
            messagebox.showerror("Error", "Username already exists. Choose a different username.")
            return False
        try:
            hashed_password = hash_password(password)
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            messagebox.showinfo("Success", "User registered successfully!")
            return True
        except sqlite3.DatabaseError as e:
            logging.error(f"Error registering user: {e}")
            messagebox.showerror("Database Error", str(e))
            return False

# Function to check user login credentials
def check_login(username, password):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and user[1] == hash_password(password):
            session["logged_in"] = True
            session["user_id"] = user[0]
            return True
        messagebox.showerror("Login failed", "Invalid username or password")
        return False

# Dialog for logging in
def login_dialog(root):
    dialog = Toplevel(root)
    dialog.title("Login")
    dialog.geometry("300x200")

    Label(dialog, text="Username:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    username_entry = Entry(dialog)
    username_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    Label(dialog, text="Password:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    password_entry = Entry(dialog, show="*")
    password_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    Button(dialog, text="Login", command=lambda: [root.deiconify(), dialog.destroy()] if check_login(username_entry.get(), password_entry.get()) else None).pack(side=tk.TOP, pady=10)
    Button(dialog, text="Register", command=lambda: registration_dialog()).pack(pady=10, padx=10, fill=tk.X)

# Logout function
def logout(root):
    session["logged_in"] = False
    session["user_id"] = None
    root.withdraw()
    login_dialog(root)

# Dialog for user registration
def registration_dialog():
    dialog = Toplevel()
    dialog.title("Register")
    dialog.geometry("300x200")

    Label(dialog, text="Username:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    username_entry = Entry(dialog)
    username_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    Label(dialog, text="Password:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    password_entry = Entry(dialog, show="*")
    password_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    Button(dialog, text="Register", command=lambda: [dialog.destroy() if register_user(username_entry.get(), password_entry.get()) else None]).pack(side=tk.TOP, pady=10)

    return dialog

# Add a new diary entry
def add_entry(title, content, date):
    if not title.strip() or not content.strip():
        messagebox.showerror("Error", "Title and content cannot be empty.")
        return
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO entries (user_id, title, content, date) VALUES (?, ?, ?, ?)', (session["user_id"], title, content, date))
            conn.commit()
        messagebox.showinfo("Success", "Entry added successfully!")
    except sqlite3.DatabaseError as e:
        logging.error(f"Error inserting entry: {e}")
        messagebox.showerror("Database Error", str(e))

# Update an existing entry
def update_entry(id, title, content, refresh_func):
    if not title.strip() or not content.strip():
        messagebox.showerror("Error", "Title and content cannot be empty.")
        return
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE entries SET title = ?, content = ? WHERE id = ? AND user_id = ?', (title, content, id, session["user_id"]))
            conn.commit()
        messagebox.showinfo("Success", "Entry updated successfully!")
        refresh_func()
    except sqlite3.DatabaseError as e:
        logging.error(f"Error updating entry: {e}")
        messagebox.showerror("Database Error", str(e))

# Delete an existing entry
def delete_entry(id, refresh_func):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM entries WHERE id = ? AND user_id = ?', (id, session["user_id"]))
            conn.commit()
        messagebox.showinfo("Deleted", "Entry deleted successfully!")
        refresh_func()
    except sqlite3.DatabaseError as e:
        logging.error(f"Error deleting entry: {e}")
        messagebox.showerror("Database Error", str(e))

# Retrieve diary entries, optionally filtered by a search term
def get_entries(filter=None):
    with get_db_connection() as conn:
        c = conn.cursor()
        if filter:
            c.execute('SELECT id, title, content, date FROM entries WHERE user_id = ? AND (title LIKE ? OR content LIKE ?) ORDER BY date DESC', (session["user_id"], '%' + filter + '%', '%' + filter + '%'))
        else:
            c.execute('SELECT id, title, content, date FROM entries WHERE user_id = ? ORDER BY date DESC', (session["user_id"],))
        return c.fetchall()

# Dialog to add a new entry
def add_entry_dialog():
    dialog = Toplevel()
    dialog.title("Add New Entry")
    dialog.geometry("400x300")

    Label(dialog, text="Title:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    title_entry = Entry(dialog)
    title_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    Label(dialog, text="Content:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    content_text = Text(dialog, height=10)
    content_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

    Button(dialog, text="Save Entry", command=lambda: save_entry(title_entry.get(), content_text.get("1.0", tk.END), dialog)).pack(side=tk.TOP, pady=10)

def save_entry(title, content, dialog):
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    add_entry(title, content, current_date)
    dialog.destroy()

# Function to view existing entries, possibly applying a filter
def view_entries():
    window = Toplevel()
    window.title("View Entries")
    window.geometry("500x400")

    scrollbar = Scrollbar(window)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = Listbox(window, yscrollcommand=scrollbar.set, width=50, height=20)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=listbox.yview)

    def refresh_listbox(filter=None):
        listbox.delete(0, tk.END)
        entries = get_entries(filter)
        for entry in entries:
            listbox.insert(tk.END, f"{entry[3]}: {entry[1]}")

    refresh_listbox()  # Initial population of the list

    listbox.bind('<<ListboxSelect>>', lambda event: on_select(event, listbox, refresh_listbox))

    Button(window, text="Refresh", command=lambda: refresh_listbox()).pack(side=tk.BOTTOM, pady=10)

# Function to handle selection events, triggering content window
def on_select(event, listbox, refresh_func):
    selection = listbox.curselection()
    if selection:
        index = selection[0]
        entry = listbox.get(index).split(": ")[1]  # Assumes format "date: title"
        content_window(entry, refresh_func)

# Content window to view, update, or delete entries
def content_window(title, refresh_func):
    entry = next((e for e in get_entries() if e[1] == title), None)
    if entry:
        dialog = Toplevel()
        dialog.title("Entry Content")
        dialog.geometry("400x300")

        Label(dialog, text="Title:").pack(side=tk.TOP, padx=10)
        title_entry = Entry(dialog)
        title_entry.insert(0, entry[1])
        title_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        text = Text(dialog, wrap=tk.WORD, height=10)
        text.insert(tk.END, entry[2])
        text.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10, expand=True)

        Button(dialog, text="Update", command=lambda: update_entry(entry[0], title_entry.get(), text.get("1.0", tk.END), dialog, refresh_func)).pack(side=tk.LEFT, padx=10, pady=10)
        Button(dialog, text="Delete", command=lambda: delete_entry(entry[0], dialog, refresh_func)).pack(side=tk.RIGHT, padx=10, pady=10)

# Update entry function with refresh call
def update_entry(id, title, content, dialog, refresh_func):
    if not title.strip() or not content.strip():
        messagebox.showerror("Error", "Title and content cannot be empty.")
        return
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE entries SET title = ?, content = ? WHERE id = ?', (title, content, id))
            conn.commit()
        messagebox.showinfo("Success", "Entry updated successfully!")
        dialog.destroy()
        refresh_func()
    except sqlite3.DatabaseError as e:
        logging.error(f"Error updating entry: {e}")
        messagebox.showerror("Database Error", str(e))

# Delete entry function with refresh call
def delete_entry(id, dialog, refresh_func):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM entries WHERE id = ?', (id,))
            conn.commit()
        messagebox.showinfo("Deleted", "Entry deleted successfully!")
        dialog.destroy()
        refresh_func()
    except sqlite3.DatabaseError as e:
        logging.error(f"Error deleting entry: {e}")
        messagebox.showerror("Database Error", str(e))

# Main application window setup
def main_window():
    root = tk.Tk()
    root.title("My Diary")
    root.geometry("300x200")
    root.withdraw()

    if not session["logged_in"]:
        login_dialog(root)

    Button(root, text="Add New Entry", command=add_entry_dialog).pack(pady=10, padx=10, fill=tk.X)
    Button(root, text="View Entries", command=lambda: view_entries()).pack(pady=10, padx=10, fill=tk.X)
    Button(root, text="Quit", command=lambda: logout(root)).pack(pady=10, padx=10, fill=tk.X)

    root.mainloop()

# Entry point of the program
if __name__ == "__main__":
    init_db()
    main_window()