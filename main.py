import tkinter as tk
from tkinter import Toplevel, Text, Entry, Button, Label, Listbox, Scrollbar, messagebox
import datetime
import sqlite3
import contextlib
import logging

logging.basicConfig(filename='diary.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

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

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                title TEXT,
                content TEXT,
                date TEXT
            )
        ''')
        conn.commit()

def add_entry(title, content, date):
    if not title.strip() or not content.strip():
        messagebox.showerror("Error", "Title and content cannot be empty.")
        return
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO entries (title, content, date) VALUES (?, ?, ?)', (title, content, date))
            conn.commit()
        messagebox.showinfo("Success", "Entry added successfully!")
    except sqlite3.DatabaseError as e:
        logging.error(f"Error inserting entry: {e}")
        messagebox.showerror("Database Error", str(e))

def update_entry(id, title, content):
    if not title.strip() or not content.strip():
        messagebox.showerror("Error", "Title and content cannot be empty.")
        return
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('UPDATE entries SET title = ?, content = ? WHERE id = ?', (title, content, id))
            conn.commit()
        messagebox.showinfo("Success", "Entry updated successfully!")
    except sqlite3.DatabaseError as e:
        logging.error(f"Error updating entry: {e}")
        messagebox.showerror("Database Error", str(e))

def delete_entry(id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM entries WHERE id = ?', (id,))
            conn.commit()
        messagebox.showinfo("Deleted", "Entry deleted successfully!")
    except sqlite3.DatabaseError as e:
        logging.error(f"Error deleting entry: {e}")
        messagebox.showerror("Database Error", str(e))

def get_entries(filter=None):
    with get_db_connection() as conn:
        c = conn.cursor()
        if filter:
            c.execute('SELECT id, title, content, date FROM entries WHERE title LIKE ? OR content LIKE ? ORDER BY date DESC', ('%' + filter + '%', '%' + filter + '%'))
        else:
            c.execute('SELECT id, title, content, date FROM entries ORDER BY date DESC')
        return c.fetchall()

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

def view_entries(filter=None):
    window = Toplevel()
    window.title("View Entries")
    window.geometry("400x300")

    scrollbar = Scrollbar(window)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = Listbox(window, yscrollcommand=scrollbar.set, width=50, height=15)
    entries = get_entries(filter)
    for entry in entries:
        listbox.insert(tk.END, f"{entry[3]}: {entry[1]}")
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=listbox.yview)

    listbox.bind('<Double-1>', lambda event: on_select(event, listbox, entries))

    search_entry = Entry(window)
    search_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

    Button(window, text="Search", command=lambda: view_entries(search_entry.get())).pack(side=tk.TOP, pady=10)

def on_select(event, listbox, entries):
    index = listbox.curselection()[0]
    entry_id = entries[index][0]
    content_window(entry_id)

def content_window(entry_id):
    entry = next((e for e in get_entries() if e[0] == entry_id), None)
    if entry:
        dialog = Toplevel()
        dialog.title("Entry Content")
        dialog.geometry("400x300")

        Label(dialog, text="Title:", font=('Arial', 14)).pack(side=tk.TOP, padx=10)
        title_entry = Entry(dialog, font=('Arial', 14))
        title_entry.insert(0, entry[1])
        title_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        text = Text(dialog, wrap=tk.WORD, height=10, width=50)
        text.insert(tk.END, entry[2])
        text.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=5, expand=True)

        Button(dialog, text="Update", command=lambda: update_entry(entry[0], title_entry.get(), text.get("1.0", tk.END))).pack(side=tk.LEFT, padx=10, pady=10)
        Button(dialog, text="Delete", command=lambda: delete_entry(entry[0]) and dialog.destroy()).pack(side=tk.RIGHT, padx=10, pady=10)

        dialog.mainloop()

def main_window():
    root = tk.Tk()
    root.title("My Diary")
    root.geometry("300x200")

    Button(root, text="Add New Entry", command=add_entry_dialog).pack(pady=10, padx=10, fill=tk.X)
    Button(root, text="View Entries", command=lambda: view_entries()).pack(pady=10, padx=10, fill=tk.X)

    root.mainloop()

if __name__ == "__main__":
    init_db()
    main_window()