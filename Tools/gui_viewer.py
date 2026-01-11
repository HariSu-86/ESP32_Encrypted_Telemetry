#!/usr/bin/env python3
"""
Tkinter GUI
Read-only viewer for esp32_logs/data.json
Shows device data in a table with auto-refresh

"""

import tkinter as tk
from tkinter import ttk
import json
import os
from datetime import datetime


DEFAULT_DATA_PATH = "../Server/esp32_logs/data.json"
REFRESH_MS = 2000 


BG_COLOR = "#1e1e1e"
FG_COLOR = "#e0e0e0"
ACCENT_COLOR = "#00d4aa"
HEADER_BG = "#2d2d2d"
TABLE_BG = "#252525"
TABLE_FG = "#ffffff"
SELECT_BG = "#005f5f"


DEVICE_COLORS = [
    "#1a3a4a",  
    "#3a2a1a",  
    "#1a3a1a",  
    "#3a1a2a",  
    "#2a1a3a",  
    "#3a3a1a",  
]

DEVICE_FG_COLORS = [
    "#00ffff",  
    "#ffaa00",  
    "#00ff00",  
    "#ff66aa",  
    "#aa66ff",  
    "#ffff00",  
]


class ESPDataViewer:
    def __init__(self, root, data_path=DEFAULT_DATA_PATH):
        self.root = root
        self.data_path = data_path
        self.last_mtime = 0
        self.device_color_map = {}
        self.color_index = 0

        # Window setup
        self.root.title("ESP32 Data Viewer")
        self.root.geometry("1000x600")
        self.root.minsize(800, 400)
        self.root.configure(bg=BG_COLOR)

        
        style = ttk.Style()
        style.theme_use('clam')
        
        
        style.configure(".", background=BG_COLOR, foreground=FG_COLOR, fieldbackground=TABLE_BG)
        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR, font=("Helvetica", 10))
        style.configure("TLabelframe", background=BG_COLOR, foreground=ACCENT_COLOR)
        style.configure("TLabelframe.Label", background=BG_COLOR, foreground=ACCENT_COLOR, font=("Helvetica", 11, "bold"))
        style.configure("TButton", background=HEADER_BG, foreground=FG_COLOR, padding=6)
        style.map("TButton", background=[("active", "#3d3d3d")])
        style.configure("TEntry", fieldbackground=TABLE_BG, foreground=TABLE_FG)
        
        
        style.configure("Treeview",
                        background=TABLE_BG,
                        foreground=TABLE_FG,
                        fieldbackground=TABLE_BG,
                        rowheight=30,
                        font=("Helvetica", 11))
        style.configure("Treeview.Heading",
                        background=HEADER_BG,
                        foreground=ACCENT_COLOR,
                        font=("Helvetica", 11, "bold"))
        style.map("Treeview",
                  background=[("selected", SELECT_BG)],
                  foreground=[("selected", "#ffffff")])

        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        header_label = tk.Label(header_frame, text="📡 ESP32 Telemetry Viewer", 
                  font=("Helvetica", 18, "bold"), bg=BG_COLOR, fg=ACCENT_COLOR)
        header_label.pack(side=tk.LEFT)

        # Status label
        self.status_var = tk.StringVar(value="Starting...")
        status_label = tk.Label(header_frame, textvariable=self.status_var, 
                  font=("Helvetica", 10), bg=BG_COLOR, fg=FG_COLOR)
        status_label.pack(side=tk.RIGHT)


        self.summary_frame = ttk.LabelFrame(main_frame, text="Device Summary", padding="5")
        self.summary_frame.pack(fill=tk.X, pady=(0, 10))


        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)


        columns = ("device_id", "type", "temperature", "humidity", "timestamp", "received_at")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)


        self.tree.heading("device_id", text="Device ID")
        self.tree.heading("type", text="Type")
        self.tree.heading("temperature", text="Temp (°C)")
        self.tree.heading("humidity", text="Humidity (%)")
        self.tree.heading("timestamp", text="ESP Time (s)")
        self.tree.heading("received_at", text="Received At")

        
        self.tree.column("device_id", width=160, anchor="center")
        self.tree.column("type", width=100, anchor="center")
        self.tree.column("temperature", width=100, anchor="center")
        self.tree.column("humidity", width=110, anchor="center")
        self.tree.column("timestamp", width=100, anchor="center")
        self.tree.column("received_at", width=180, anchor="center")

        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)


        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(footer_frame, text="⟳ Refresh Now", 
                   command=self.load_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(footer_frame, text="✕ Clear View", 
                   command=self.clear_view).pack(side=tk.LEFT, padx=5)

        
        path_label = tk.Label(footer_frame, text="Data file:", bg=BG_COLOR, fg=FG_COLOR)
        path_label.pack(side=tk.LEFT, padx=(20, 5))
        self.path_var = tk.StringVar(value=self.data_path)
        path_entry = tk.Entry(footer_frame, textvariable=self.path_var, width=40,
                              bg=TABLE_BG, fg=TABLE_FG, insertbackground=TABLE_FG)
        path_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(footer_frame, text="Set Path", 
                   command=self.update_path).pack(side=tk.LEFT, padx=5)

        # Record count
        self.count_var = tk.StringVar(value="Records: 0")
        count_label = tk.Label(footer_frame, textvariable=self.count_var, 
                               bg=BG_COLOR, fg=ACCENT_COLOR, font=("Helvetica", 10, "bold"))
        count_label.pack(side=tk.RIGHT, padx=10)

        
        for i, (bg, fg) in enumerate(zip(DEVICE_COLORS, DEVICE_FG_COLORS)):
            self.tree.tag_configure(f"device_{i}", background=bg, foreground=fg)

        # Start auto-refresh
        self.load_data()
        self.schedule_refresh()

    def get_device_color_tag(self, device_id):
        
        if device_id not in self.device_color_map:
            self.device_color_map[device_id] = f"device_{self.color_index % len(DEVICE_COLORS)}"
            self.color_index += 1
        return self.device_color_map[device_id]

    def load_data(self):
        
        try:
            if not os.path.exists(self.data_path):
                self.status_var.set(f"File not found: {self.data_path}")
                return

            mtime = os.path.getmtime(self.data_path)
            if mtime == self.last_mtime:
                return  # No changes
            self.last_mtime = mtime

            with open(self.data_path, 'r') as f:
                data = json.load(f)

            # Handle both formats: {"all_data": [...]} or [...]
            if isinstance(data, dict):
                records = data.get('all_data', [])
            else:
                records = data if isinstance(data, list) else [data]

            
            for item in self.tree.get_children():
                self.tree.delete(item)

            
            device_stats = {}

            
            for record in reversed(records):
                device_id = record.get('device_id', 'Unknown')
                rec_type = record.get('type', '-')
                temp = record.get('temperature', '-')
                humidity = record.get('humidity', '-')
                timestamp = record.get('timestamp', '-')
                received_at = record.get('received_at', '-')

                
                if isinstance(temp, (int, float)):
                    temp = f"{temp:.1f}"
                if isinstance(humidity, (int, float)):
                    humidity = f"{humidity:.1f}"
                if isinstance(received_at, str) and 'T' in received_at:
                    # Shorten ISO format
                    received_at = received_at.replace('T', ' ')[:19]

                
                tag = self.get_device_color_tag(device_id)

                self.tree.insert("", "end", values=(
                    device_id, rec_type, temp, humidity, timestamp, received_at
                ), tags=(tag,))

                
                if device_id not in device_stats:
                    device_stats[device_id] = {'count': 0, 'last_temp': temp, 'last_humidity': humidity}
                device_stats[device_id]['count'] += 1
                device_stats[device_id]['last_temp'] = temp
                device_stats[device_id]['last_humidity'] = humidity

            
            self.update_summary(device_stats)

            
            self.count_var.set(f"Records: {len(records)}")
            self.status_var.set(f"Last update: {datetime.now().strftime('%H:%M:%S')}")

        except json.JSONDecodeError as e:
            self.status_var.set(f"JSON error: {e}")
        except Exception as e:
            self.status_var.set(f"Error: {e}")

    def update_summary(self, device_stats):
        """Update the device summary panel."""
        # Clear existing summary widgets
        for widget in self.summary_frame.winfo_children():
            widget.destroy()

        if not device_stats:
            no_dev = tk.Label(self.summary_frame, text="No devices detected", 
                              bg=BG_COLOR, fg=FG_COLOR, font=("Helvetica", 10))
            no_dev.pack()
            return

        for device_id, stats in device_stats.items():
            color_tag = self.get_device_color_tag(device_id)
            color_idx = int(color_tag.split('_')[1])
            bg_color = DEVICE_COLORS[color_idx]
            fg_color = DEVICE_FG_COLORS[color_idx]

            frame = tk.Frame(self.summary_frame, bg=bg_color, relief="ridge", bd=2)
            frame.pack(side=tk.LEFT, padx=5, pady=2, fill=tk.Y)

            tk.Label(frame, text=f"📡 {device_id}", font=("Helvetica", 10, "bold"), 
                     bg=bg_color, fg=fg_color).pack(padx=8, pady=3)
            tk.Label(frame, text=f"Msgs: {stats['count']}", font=("Helvetica", 9), 
                     bg=bg_color, fg=fg_color).pack(padx=8)
            tk.Label(frame, text=f"Temp: {stats['last_temp']}°C", font=("Helvetica", 9), 
                     bg=bg_color, fg=fg_color).pack(padx=8)
            tk.Label(frame, text=f"Hum: {stats['last_humidity']}%", font=("Helvetica", 9), 
                     bg=bg_color, fg=fg_color).pack(padx=8, pady=(0, 3))

    def clear_view(self):
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.count_var.set("Records: 0")

    def update_path(self):
        
        new_path = self.path_var.get().strip()
        if new_path:
            self.data_path = new_path
            self.last_mtime = 0  # Force reload
            self.load_data()

    def schedule_refresh(self):
        
        self.load_data()
        self.root.after(REFRESH_MS, self.schedule_refresh)


def main():
    import sys

    # Allow custom path from command line
    data_path = DEFAULT_DATA_PATH
    if len(sys.argv) > 1:
        data_path = sys.argv[1]

    root = tk.Tk()
    app = ESPDataViewer(root, data_path)
    root.mainloop()


if __name__ == "__main__":
    main()
