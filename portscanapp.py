import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from scanner import PortScanner
import utils
import os
import threading
import json
import csv

class PortScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PortScanApp - GUI Port Scanner")
        self.root.geometry("900x700")
        self.is_fullscreen = False
        
        # Bind F11 for fullscreen toggle
        self.root.bind('<F11>', self.toggle_fullscreen)
        
        self.create_widgets()
        self.create_menu()
        self.scan_results = {}
        self.scanning = False
        self.stop_event = threading.Event()

    def create_widgets(self):
        # Configure grid weights for proper scaling
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)  # Results frame should expand

        # Input Frame
        input_frame = ttk.Frame(self.root)
        input_frame.grid(row=0, column=0, columnspan=3, sticky='ew', padx=5, pady=5)

        ttk.Label(input_frame, text="Target IP / Domain:").pack(side='left', padx=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.pack(side='left', padx=5)

        ttk.Label(input_frame, text="Port Range (e.g., 20-80):").pack(side='left', padx=5)
        self.port_entry = ttk.Entry(input_frame, width=30)
        self.port_entry.pack(side='left', padx=5)

        # Button Frame
        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=1, column=0, columnspan=3, sticky='ew', padx=5, pady=5)

        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side='left', padx=5)

        self.cancel_button = ttk.Button(button_frame, text="Cancel Scan", command=self.cancel_scan, state='disabled')
        self.cancel_button.pack(side='left', padx=5)

        self.export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        self.export_button.pack(side='left', padx=5)

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=2, column=0, columnspan=3, sticky='ew', padx=5, pady=5)

        # Results Frame with Scrollbar
        results_frame = ttk.Frame(self.root)
        results_frame.grid(row=3, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(results_frame)
        scrollbar.pack(side='right', fill='y')

        self.result_text = tk.Text(results_frame, height=20, width=60, yscrollcommand=scrollbar.set)
        self.result_text.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.result_text.yview)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief='sunken')
        self.status_bar.grid(row=4, column=0, columnspan=3, sticky='ew')

    def start_scan(self):
        if self.scanning:
            return

        target = self.target_entry.get()
        port_range = self.port_entry.get()

        if not utils.validate_target(target):
            messagebox.showerror("Invalid Input", "Please enter a valid IP address or domain.")
            return

        ports = utils.parse_port_range(port_range)
        if ports is None:
            messagebox.showerror("Invalid Input", "Please enter a valid port range.")
            return

        self.scanning = True
        self.stop_event.clear()
        self.start_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.progress_var.set(0)
        self.status_var.set("Scanning...")
        self.result_text.delete(1.0, tk.END)

        # Start scan in a separate thread
        threading.Thread(target=self._run_scan, args=(target, ports), daemon=True).start()

    def _run_scan(self, target, ports):
        self.status_var.set("Scan in progress:)")
        def progress_callback(scanned, total):
            progress = (scanned / total) * 100
            self.root.after(0, lambda: self.progress_var.set(progress))

        scanner = PortScanner(target, ports, progress_callback=progress_callback, stop_event=self.stop_event)
        results = scanner.scan_with_banner()

        if not self.stop_event.is_set():
            self.root.after(0, lambda: self._display_results(results))

    def _display_results(self, results):
        for port, banner in results.items():
            self.result_text.insert(tk.END, f"Port {port} is open - Banner: {banner}\n")

        self.scan_results = results
        self.status_var.set("Scan Complete")
        self.start_button.config(state='normal')
        self.cancel_button.config(state='disabled')
        self.scanning = False

    def cancel_scan(self):
        if self.scanning:
            self.stop_event.set()
            self.status_var.set("Scan Cancelled")
            self.start_button.config(state='normal')
            self.cancel_button.config(state='disabled')
            self.scanning = False

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Fullscreen (F11)", command=self.toggle_fullscreen)

    def toggle_fullscreen(self, event=None):
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes('-fullscreen', self.is_fullscreen)

    def export_results(self):
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("JSON files", "*.json"), ("XML files", "*.xml")],
                                                 initialdir=os.path.join(os.getcwd(), "exports"),
                                                 title="Save scan results")
        if filepath:
            try:
                ext = os.path.splitext(filepath)[1].lower()
                if ext == '.json':
                    with open(filepath, 'w') as f:
                        json.dump(self.scan_results, f, indent=4)
                elif ext == '.csv':
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Port", "Banner"])
                        for port, banner in self.scan_results.items():
                            writer.writerow([port, banner])
                elif ext == '.xml':
                    with open(filepath, 'w') as f:
                        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                        f.write('<scan_results>\n')
                        for port, banner in self.scan_results.items():
                            f.write(f'  <port number="{port}">{banner}</port>\n')
                        f.write('</scan_results>\n')
                else:  # .txt
                    with open(filepath, 'w') as f:
                        f.write("Open Ports with Banners:\n")
                        for port, banner in self.scan_results.items():
                            f.write(f"Port {port} is open - Banner: {banner}\n")
                messagebox.showinfo("Success", f"Results exported to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanApp(root)
    root.mainloop()
