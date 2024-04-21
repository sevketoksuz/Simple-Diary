import tkinter as tk
from tkinter import simpledialog, Toplevel, Text, Button, messagebox
import datetime
import sqlite3

def init_db():
    conn = sqlite3.connect('diary.db')
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
    conn.close()

def add_entry(title, content, date):
    conn = sqlite3.connect('diary.db')
    c = conn.cursor()
    c.execute('INSERT INTO entries (title, content, date) VALUES (?, ?, ?)', (title, content, date))
    conn.commit()
    conn.close()

def update_entry(id, title, content):
    conn = sqlite3.connect('diary.db')
    c = conn.cursor()
    c.execute('UPDATE entries SET title = ?, content = ? WHERE id = ?', (title, content, id))
    conn.commit()
    conn.close()

def delete_entry(id):
    conn = sqlite3.connect('diary.db')
    c = conn.cursor()
    c.execute('DELETE FROM entries WHERE id = ?', (id,))
    conn.commit()
    conn.close()

def get_entries():
    conn = sqlite3.connect('diary.db')
    c = conn.cursor()
    c.execute('SELECT id, title, content, date FROM entries ORDER BY date DESC')
    entries = c.fetchall()
    conn.close()
    return entries

def add_entry_dialog():
    def save_entry():
        content = content_text.get("1.0", tk.END)
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        add_entry(title_entry.get(), content, current_date)
        dialog.destroy()
        messagebox.showinfo("Saved", "Entry added successfully!")

    dialog = Toplevel()
    dialog.title("Add New Entry")
    
    tk.Label(dialog, text="Title:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    title_entry = tk.Entry(dialog)
    title_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    
    tk.Label(dialog, text="Content:").pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    content_text = Text(dialog, height=10)
    content_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    save_button = Button(dialog, text="Save Entry", command=save_entry)
    save_button.pack(side=tk.TOP, pady=10)

    dialog.mainloop()

def view_entries():
    window = Toplevel()
    window.title("View Entries")
    
    scrollbar = tk.Scrollbar(window)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = tk.Listbox(window, yscrollcommand=scrollbar.set, width=50, height=15)
    entries = get_entries()
    for entry in entries:
        listbox.insert(tk.END, f"{entry[3]}: {entry[1]}")

    listbox.pack(side=tk.LEFT, fill=tk.BOTH)
    scrollbar.config(command=listbox.yview)

    def on_select(event):
        widget = event.widget
        index = int(widget.curselection()[0])
        entry_id = entries[index][0]
        content_window(entry_id)

    listbox.bind('<<ListboxSelect>>', on_select)

    window.mainloop()

def content_window(entry_id):
    entry = next((e for e in get_entries() if e[0] == entry_id), None)
    if entry:
        dialog = Toplevel()
        dialog.title("Entry Content")

        tk.Label(dialog, text="Title:", font=('Arial', 14)).pack(side=tk.TOP, padx=10)
        title_entry = tk.Entry(dialog, font=('Arial', 14))
        title_entry.insert(0, entry[1])
        title_entry.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        text = Text(dialog, wrap=tk.WORD, height=10, width=50)
        text.insert(tk.END, entry[2])
        text.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=5, expand=True)
        
        update_button = Button(dialog, text="Update", command=lambda: update_entry(entry[0], title_entry.get(), text.get("1.0", tk.END)))
        update_button.pack(side=tk.LEFT, padx=10, pady=10)
        
        delete_button = Button(dialog, text="Delete", command=lambda: [delete_entry(entry[0]), dialog.destroy(), messagebox.showinfo("Deleted", "Entry deleted successfully!")])
        delete_button.pack(side=tk.RIGHT, padx=10, pady=10)

        dialog.mainloop()

def main_window():
    root = tk.Tk()
    root.title("My Diary")
    root.geometry("300x200")  # Adjust size as needed

    # Button to add a new entry
    add_button = tk.Button(root, text="Add New Entry", command=add_entry_dialog)
    add_button.pack(pady=10, padx=10, fill=tk.X)

    # Button to view all entries
    view_button = tk.Button(root, text="View Entries", command=view_entries)
    view_button.pack(pady=10, padx=10, fill=tk.X)

    root.mainloop()


if __name__ == "__main__":
    init_db()
    main_window()
