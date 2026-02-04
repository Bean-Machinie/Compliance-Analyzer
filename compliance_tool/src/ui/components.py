import tkinter as tk
from tkinter import ttk


def labeled_frame(parent: tk.Widget, text: str) -> ttk.Labelframe:
    frame = ttk.Labelframe(parent, text=text, padding=8)
    frame.pack(fill="both", expand=True, padx=8, pady=6)
    return frame


def make_listbox(parent: tk.Widget, height: int = 8) -> tk.Listbox:
    listbox = tk.Listbox(parent, height=height)
    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=listbox.yview)
    listbox.configure(yscrollcommand=scrollbar.set)
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    return listbox


def make_tree(parent: tk.Widget, columns: list, headings: list) -> ttk.Treeview:
    tree = ttk.Treeview(parent, columns=columns, show="headings")
    for col, heading in zip(columns, headings):
        tree.heading(col, text=heading)
        tree.column(col, anchor="w", width=150)
    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    return tree
