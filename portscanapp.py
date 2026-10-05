from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import exports
import utils
from scanner import PortScanner


class PortScanApp:
    UI_POLL_INTERVAL_MS = 50

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PortScanApp - GUI Port Scanner")
        self.root.geometry("900x700")
        self.root.minsize(700, 450)

        self.is_fullscreen = False
        self.scan_results: dict[int, str] = {}
        self.scanning = False
        self._closing = False
        self._scan_id = 0
        self._scanner: PortScanner | None = None
        self._scan_thread: threading.Thread | None = None
        self._ui_events: queue.Queue[tuple[object, ...]] = queue.Queue()

        self.root.bind("<F11>", self.toggle_fullscreen)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.create_widgets()
        self.create_menu()
        self.root.after(self.UI_POLL_INTERVAL_MS, self._process_ui_events)

    def create_widgets(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        input_frame = ttk.Frame(self.root)
        input_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        ttk.Label(input_frame, text="Target IP / Domain:").pack(side="left", padx=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.pack(side="left", padx=5)

        ttk.Label(input_frame, text="Ports (e.g., 22,80-100,443):").pack(
            side="left", padx=5
        )
        self.port_entry = ttk.Entry(input_frame, width=30)
        self.port_entry.pack(side="left", padx=5)

        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        self.start_button = ttk.Button(
            button_frame, text="Start Scan", command=self.start_scan
        )
        self.start_button.pack(side="left", padx=5)

        self.cancel_button = ttk.Button(
            button_frame,
            text="Cancel Scan",
            command=self.cancel_scan,
            state="disabled",
        )
        self.cancel_button.pack(side="left", padx=5)

        self.export_button = ttk.Button(
            button_frame,
            text="Export Results",
            command=self.export_results,
            state="disabled",
        )
        self.export_button.pack(side="left", padx=5)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            self.root, variable=self.progress_var, maximum=100
        )
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        results_frame = ttk.Frame(self.root)
        results_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(results_frame)
        scrollbar.pack(side="right", fill="y")

        self.result_text = tk.Text(
            results_frame,
            height=20,
            width=60,
            yscrollcommand=scrollbar.set,
            wrap="word",
        )
        self.result_text.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.result_text.yview)

        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(
            self.root, textvariable=self.status_var, relief="sunken", anchor="w"
        )
        self.status_bar.grid(row=4, column=0, sticky="ew")

    def create_menu(self) -> None:
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(
            label="Toggle Fullscreen (F11)", command=self.toggle_fullscreen
        )

    def _set_scanning_controls(self, scanning: bool) -> None:
        self.start_button.config(state="disabled" if scanning else "normal")
        self.cancel_button.config(state="normal" if scanning else "disabled")
        self.target_entry.config(state="disabled" if scanning else "normal")
        self.port_entry.config(state="disabled" if scanning else "normal")
        export_state = "normal" if self.scan_results and not scanning else "disabled"
        self.export_button.config(state=export_state)

    def start_scan(self) -> None:
        if self.scanning:
            return

        target = self.target_entry.get().strip()
        if not utils.validate_target(target):
            messagebox.showerror(
                "Invalid Input", "Please enter a valid IP address or domain."
            )
            return

        ports = utils.parse_port_range(self.port_entry.get())
        if ports is None:
            messagebox.showerror(
                "Invalid Input", "Please enter valid ports from 1 to 65535."
            )
            return

        self._scan_id += 1
        scan_id = self._scan_id
        stop_event = threading.Event()

        def progress_callback(scanned: int, total: int) -> None:
            self._ui_events.put(("progress", scan_id, scanned, total))

        self._scanner = PortScanner(
            target,
            ports,
            progress_callback=progress_callback,
            stop_event=stop_event,
        )
        self.scan_results = {}
        self.scanning = True
        self.progress_var.set(0)
        self.status_var.set(f"Scanning {target} ({utils.format_port_count(ports)})...")
        self.result_text.delete("1.0", tk.END)
        self._set_scanning_controls(True)

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, self._scanner),
            daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, scan_id: int, scanner: PortScanner) -> None:
        try:
            results = scanner.scan_with_banner()
        except Exception as exc:
            self._ui_events.put(("error", scan_id, str(exc)))
            return

        event_type = "cancelled" if scanner.stop_event.is_set() else "complete"
        self._ui_events.put((event_type, scan_id, results))

    def _process_ui_events(self) -> None:
        if self._closing:
            return

        while True:
            try:
                event = self._ui_events.get_nowait()
            except queue.Empty:
                break

            event_type, scan_id, *payload = event
            if scan_id != self._scan_id:
                continue

            if event_type == "progress" and self.scanning:
                scanned, total = payload
                self.progress_var.set((int(scanned) / int(total)) * 100)
            elif event_type == "complete":
                self.progress_var.set(100)
                self._finish_scan(payload[0], "Scan complete")
            elif event_type == "cancelled":
                self._finish_scan(payload[0], "Scan cancelled")
            elif event_type == "error":
                self._finish_scan({}, "Scan failed")
                messagebox.showerror("Scan Error", str(payload[0]))

        self.root.after(self.UI_POLL_INTERVAL_MS, self._process_ui_events)

    def _finish_scan(self, results: object, status: str) -> None:
        self.scan_results = dict(results) if isinstance(results, dict) else {}
        self.scanning = False
        self._scanner = None
        self._scan_thread = None
        self._display_results(self.scan_results)
        self.status_var.set(status)
        self._set_scanning_controls(False)

    def _display_results(self, results: dict[int, str]) -> None:
        self.result_text.delete("1.0", tk.END)
        if not results:
            self.result_text.insert(tk.END, "No open ports found.\n")
            return
        for port, banner in sorted(results.items()):
            self.result_text.insert(
                tk.END, f"Port {port} is open - Banner: {banner}\n"
            )

    def cancel_scan(self) -> None:
        if not self.scanning or self._scanner is None:
            return
        self.status_var.set("Cancelling scan...")
        self.cancel_button.config(state="disabled")
        self._scanner.cancel()

    def toggle_fullscreen(self, event: tk.Event | None = None) -> None:
        del event
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes("-fullscreen", self.is_fullscreen)

    def export_results(self) -> None:
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return

        export_directory = Path.cwd() / "exports"
        try:
            export_directory.mkdir(exist_ok=True)
            initial_directory = export_directory
        except OSError:
            initial_directory = Path.cwd()

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("XML files", "*.xml"),
            ],
            initialdir=str(initial_directory),
            title="Save scan results",
        )
        if not filepath:
            return

        try:
            exports.export_results(filepath, self.scan_results)
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to save file: {exc}")
            return
        messagebox.showinfo("Success", f"Results exported to {filepath}")

    def close(self) -> None:
        self._closing = True
        if self._scanner is not None:
            self._scanner.cancel()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanApp(root)
    root.mainloop()
