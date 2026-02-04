import tkinter as tk
from tkinter import ttk


class FiltersPanel(ttk.Frame):
    def __init__(self, parent: tk.Widget, on_change):
        super().__init__(parent)
        self.on_change = on_change

        self.view_var = tk.StringVar(value="Requirements -> Test Cases")
        self.theme_var = tk.StringVar(value="Light")
        self.stakeholder_var = tk.StringVar(value="All")
        self.prefix_var = tk.StringVar(value="All")
        self.coverage_var = tk.StringVar(value="All")
        self.test_case_var = tk.StringVar(value="")
        self.search_var = tk.StringVar(value="")

        self._all_requirements = []

        self._build()

    def _build(self) -> None:
        ttk.Label(self, text="View").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        view_combo = ttk.Combobox(
            self,
            textvariable=self.view_var,
            values=["Requirements -> Test Cases", "Test Case Context"],
            state="readonly",
            width=24,
        )
        view_combo.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Theme").grid(row=0, column=2, sticky="w", padx=4, pady=4)
        theme_combo = ttk.Combobox(
            self,
            textvariable=self.theme_var,
            values=["Light", "Dark"],
            state="readonly",
            width=10,
        )
        theme_combo.grid(row=0, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Stakeholder").grid(row=0, column=4, sticky="w", padx=4, pady=4)
        self.stakeholder_combo = ttk.Combobox(self, textvariable=self.stakeholder_var, values=["All"], state="readonly", width=16)
        self.stakeholder_combo.grid(row=0, column=5, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Prefix").grid(row=0, column=6, sticky="w", padx=4, pady=4)
        self.prefix_combo = ttk.Combobox(self, textvariable=self.prefix_var, values=["All", "BNC", "DLS", "NSE"], state="readonly", width=10)
        self.prefix_combo.grid(row=0, column=7, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Coverage").grid(row=0, column=8, sticky="w", padx=4, pady=4)
        self.coverage_combo = ttk.Combobox(self, textvariable=self.coverage_var, values=["All", "Covered", "Uncovered"], state="readonly", width=12)
        self.coverage_combo.grid(row=0, column=9, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Test Case").grid(row=0, column=10, sticky="w", padx=4, pady=4)
        self.test_case_combo = ttk.Combobox(self, textvariable=self.test_case_var, values=[""], state="readonly", width=12)
        self.test_case_combo.grid(row=0, column=11, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Search Req").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        search_entry = ttk.Entry(self, textvariable=self.search_var, width=22)
        search_entry.grid(row=1, column=1, sticky="w", padx=4, pady=4)
        ttk.Button(self, text="Apply", command=self._apply_search).grid(row=1, column=2, sticky="w", padx=4, pady=4)

        ttk.Label(self, text="Requirements").grid(row=1, column=3, sticky="w", padx=4, pady=4)
        list_frame = ttk.Frame(self)
        list_frame.grid(row=1, column=4, columnspan=8, sticky="w", padx=4, pady=4)
        self.req_listbox = tk.Listbox(list_frame, height=4, selectmode="extended", width=60)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.req_listbox.yview)
        self.req_listbox.configure(yscrollcommand=scroll.set)
        self.req_listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        for widget in (
            view_combo,
            theme_combo,
            self.stakeholder_combo,
            self.prefix_combo,
            self.coverage_combo,
            self.test_case_combo,
        ):
            widget.bind("<<ComboboxSelected>>", lambda _event: self.on_change())
        self.req_listbox.bind("<<ListboxSelect>>", lambda _event: self.on_change())
        search_entry.bind("<Return>", lambda _event: self._apply_search())

    def set_stakeholders(self, stakeholders):
        values = ["All"] + sorted([s for s in stakeholders if s])
        self.stakeholder_combo["values"] = values
        if self.stakeholder_var.get() not in values:
            self.stakeholder_var.set("All")

    def set_test_cases(self, test_cases):
        values = [""] + sorted([t for t in test_cases if t])
        self.test_case_combo["values"] = values
        if self.test_case_var.get() not in values:
            self.test_case_var.set("")

    def set_requirements(self, requirements):
        self._all_requirements = sorted(requirements)
        self._apply_search()

    def _apply_search(self) -> None:
        query = self.search_var.get().strip().upper()
        self.req_listbox.delete(0, tk.END)
        for req_id in self._all_requirements:
            if not query or query in req_id.upper():
                self.req_listbox.insert(tk.END, req_id)
        self.on_change()

    def get_filters(self):
        selected = [self.req_listbox.get(i) for i in self.req_listbox.curselection()]
        return {
            "view": self.view_var.get(),
            "theme": self.theme_var.get(),
            "stakeholder": self.stakeholder_var.get(),
            "prefix": self.prefix_var.get(),
            "coverage": self.coverage_var.get(),
            "test_case": self.test_case_var.get(),
            "requirements": selected,
        }
