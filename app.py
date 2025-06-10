import configparser
import os
import platform
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font, filedialog
from threading import Thread, Lock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sklearn.ensemble import IsolationForest
import psutil
import subprocess
import logging
import re
from datetime import datetime
from pathlib import Path

# Define project root and logs directory
PROJECT_ROOT = Path(__file__).parent
LOGS_DIR = PROJECT_ROOT / 'logs'
CONFIG_DIR = PROJECT_ROOT / 'config'

# Ensure directories exist
LOGS_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('RansomwareDetector')

# Color scheme
COLORS = {
    'dark_bg': '#1e1e1e',
    'darker_bg': '#181818',
    'panel_bg': '#252526',
    'text_fg': '#ffffff',
    'behavioral': '#4fc3f7',
    'anomaly': '#ffb74d',
    'signature': '#81c784',
    'header': '#0078d7',
    'status_bg': '#252526',
    'button_bg': '#333333',
    'button_active': '#3e3e3e'
}

def safe_float_convert(value, default=0.0, min_val=None, max_val=None):
    try:
        cleaned_value = re.sub(r'[^\d.-]', '', str(value))
        num = float(cleaned_value)
        if min_val is not None:
            num = max(min_val, num)
        if max_val is not None:
            num = min(max_val, num)
        return num
    except (ValueError, TypeError):
        logger.warning(f"Could not convert '{value}' to float, using default {default}")
        return default

class SystemFonts:
    @staticmethod
    def get_default_fonts():
        system = platform.system()
        base_font = 'Segoe UI' if system == "Windows" else 'Helvetica' if system == "Darwin" else 'Ubuntu'
        return {
            'small': (base_font, 9),
            'regular': (base_font, 10),
            'bold': (base_font, 10, 'bold'),
            'title': (base_font, 12, 'bold'),
            'large': (base_font, 14, 'bold')
        }

class DetectionCounter:
    def __init__(self):
        self.counts = {'behavioral': 0, 'anomaly': 0, 'signature': 0}
        self.lock = Lock()
    
    def increment(self, detection_type):
        with self.lock:
            self.counts[detection_type] += 1
    
    def get_count(self, detection_type):
        with self.lock:
            return self.counts[detection_type]
    
    def reset(self):
        with self.lock:
            for key in self.counts:
                self.counts[key] = 0

class BehaviorTracker:
    def __init__(self, max_history=50):
        self.max_history = max_history
        self.recent_behaviors = set()
        self.lock = Lock()
    
    def add_behavior(self, behavior):
        with self.lock:
            if behavior not in self.recent_behaviors:
                self.recent_behaviors.add(behavior)
                if len(self.recent_behaviors) > self.max_history:
                    self.recent_behaviors.pop()
                return True
            return False
    
    def clear(self):
        with self.lock:
            self.recent_behaviors.clear()

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self, gui, monitored_dirs, excluded_dirs):
        self.gui = gui
        self.monitored_dirs = [os.path.expanduser(d) for d in monitored_dirs]
        self.excluded_dirs = [os.path.expanduser(d) for d in excluded_dirs]
        self.observers = []
        self.behavior_tracker = BehaviorTracker()
        
        # Validate monitored directories
        for d in self.monitored_dirs:
            if not os.path.exists(d):
                logger.warning(f"Monitored directory {d} does not exist. Creating it.")
                os.makedirs(d, exist_ok=True)
    
    def on_modified(self, event):
        if not event.is_directory and not any(event.src_path.startswith(excl) for excl in self.excluded_dirs):
            msg = f'File modified: {event.src_path}'
            if self.behavior_tracker.add_behavior(msg):
                self.gui.log('behavioral', msg)
            
    def on_created(self, event):
        if not event.is_directory and not any(event.src_path.startswith(excl) for excl in self.excluded_dirs):
            msg = f'File created: {event.src_path}'
            if self.behavior_tracker.add_behavior(msg):
                self.gui.log('behavioral', msg)
            
    def on_deleted(self, event):
        if not event.is_directory and not any(event.src_path.startswith(excl) for excl in self.excluded_dirs):
            msg = f'File deleted: {event.src_path}'
            if self.behavior_tracker.add_behavior(msg):
                self.gui.log('behavioral', msg)
        
    def start_monitoring(self):
        for directory in self.monitored_dirs:
            if os.path.exists(directory):
                observer = Observer()
                observer.schedule(self, directory, recursive=True)
                observer.start()
                self.observers.append(observer)
                logger.info(f"Started monitoring: {directory}")
            else:
                logger.warning(f"Directory does not exist: {directory}")
                
    def stop_monitoring(self):
        for observer in self.observers:
            observer.stop()
            observer.join()
        self.observers = []
        logger.info("Stopped all monitoring")
        self.behavior_tracker.clear()

class RansomwareStyledGUI:
    def __init__(self, root):
        self.root = root
        self.fonts = SystemFonts.get_default_fonts()
        self.counter = DetectionCounter()
        self.view_mode = 'parallel'
        self.matched_files = set()
        
        self.setup_window()
        self.load_config()
        self.setup_logging()
        self.setup_anomaly_model()
        self.setup_styles()
        self.create_widgets()
        self.update_view_mode()
        
        self.root.bind('<Configure>', self.on_window_resize)
        
    def setup_window(self):
        self.root.title("Ransomware Detection System")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=COLORS['dark_bg'])
        self.running = False
        self.detector = None
        
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def on_window_resize(self, event):
        if event.widget == self.root:
            self.update_view_layout()
    
    def update_view_layout(self):
        if self.view_mode == 'parallel':
            width = self.root.winfo_width()
            padx = 5 if width < 1000 else 10 if width < 1200 else 15
            for child in self.main_container.winfo_children():
                child.grid_configure(padx=padx)
    
    def load_config(self):
        self.config = configparser.ConfigParser()
        config_path = CONFIG_DIR / "config.ini"
        
        if not os.path.exists(config_path):
            self.create_default_config(config_path)
            
        self.config.read(config_path)
        
        monitored = self.config.get('Settings', 'monitored_dirs', fallback='~/Documents,~/test_files').split(',')
        self.monitored_dirs = [os.path.expanduser(d.strip()) for d in monitored if d.strip()]
        
        excluded = self.config.get('Settings', 'excluded_dirs', fallback='/proc,/sys,/dev,/tmp').split(',')
        self.excluded_dirs = [os.path.expanduser(d.strip()) for d in excluded if d.strip()]
        
        self.yara_rule = os.path.expanduser(
            self.config.get('Settings', 'yara_rule', fallback=str(CONFIG_DIR / 'ransomware_rule.yar')))
        
        self.cpu_threshold = safe_float_convert(
            self.config.get('Settings', 'cpu_threshold', fallback=70),
            default=70,
            min_val=0,
            max_val=100
        )
        
        self.anomaly_contamination = safe_float_convert(
            self.config.get('Settings', 'anomaly_contamination', fallback=0.05),
            default=0.05,
            min_val=0.01,
            max_val=0.5
        )
        
        self.enable_sound = self.config.getboolean('Settings', 'enable_sound', fallback=False)
        
        for directory in self.monitored_dirs:
            os.makedirs(directory, exist_ok=True)
        
    def setup_logging(self):
        try:
            log_file = LOGS_DIR / f'ransomware_detection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)
            logger.info(f"Logging initialized to file: {log_file}")
        except Exception as e:
            logger.error(f"Failed to setup file logging: {str(e)}")
            logger.info("Using console logging only")
        
    def create_default_config(self, config_path):
        self.config['Settings'] = {
            'monitored_dirs': '~/Documents,~/test_files',
            'excluded_dirs': '/proc,/sys,/dev,/tmp',
            'yara_rule': str(CONFIG_DIR / 'ransomware_rule.yar'),
            'cpu_threshold': '70',
            'anomaly_contamination': '0.05',
            'enable_sound': 'false'
        }
        with open(config_path, 'w') as f:
            self.config.write(f)
        logger.info(f"Created default config file at {config_path}")
        
    def setup_anomaly_model(self):
        self.model_data = [
            [5, 0.05], [10, 0.1], [15, 0.15], [20, 0.2],  # Normal
            [40, 0.5], [50, 0.6], [55, 0.65], [58, 0.7], [60, 0.8], [100, 1.0]  # Ransomware
        ]
        try:
            self.model = IsolationForest(
                # contamination=self.anomaly_contamination,
                contamination=0.15,
                random_state=42,
                n_estimators=500,
                max_samples='auto'
            )
            self.model.fit(self.model_data)
            logger.info(f"Anomaly model trained with contamination={self.anomaly_contamination}")
        except Exception as e:
            logger.error(f"Anomaly model error: {str(e)}")
            self.model = IsolationForest(contamination=0.05, random_state=42)
            self.model.fit(self.model_data)
    
    def monitor_loop(self):
        while self.running:
            try:
                cpu = psutil.cpu_percent(interval=0.5)
                if cpu > self.cpu_threshold:
                    self.log('behavioral', f"High CPU usage detected: {cpu}%")
                
                total_files = 0
                file_list = []
                try:
                    for directory in self.monitored_dirs:
                        logger.debug(f"Scanning directory: {directory}")
                        for root, _, files in os.walk(directory):
                            if not any(root.startswith(excl) for excl in self.excluded_dirs):
                                total_files += len(files)
                                file_list.extend([os.path.join(root, f) for f in files])
                                logger.debug(f"Found {len(files)} files in {root}")
                except Exception as e:
                    logger.error(f"File count error: {e}")
                    continue

                try:
                    cpu = psutil.cpu_percent(interval=0.1)
                    logger.debug(f"Total files: {total_files}, CPU: {cpu}, Files: {file_list}")
                    if total_files >= 30 and cpu >= 70:
                        test_point = [[total_files, cpu / 100]]
                        logger.debug(f"Preparing anomaly test: {test_point}")
                        try:
                            prediction = self.model.predict(test_point)
                            anomaly_score = self.model.decision_function(test_point)[0]
                            logger.debug(f"Anomaly test: files={total_files}, cpu={cpu}, score={anomaly_score:.2f}, prediction={prediction}")
                            if prediction[0] == -1 and anomaly_score < -0.05:
                                self.log('anomaly',
                                        f"ANOMALY DETECTED! Files: {total_files}, CPU: {cpu}%, "
                                        f"Score: {anomaly_score:.2f}")
                        except Exception as e:
                            logger.error(f"Anomaly detection error: {e}")
                            self.log('behavioral', f"Anomaly detection error: {str(e)}")
                except Exception as e:
                    logger.error(f"CPU or monitor error: {e}")

                for directory in self.monitored_dirs:
                    try:
                        for root, _, files in os.walk(directory):
                            if not any(root.startswith(excl) for excl in self.excluded_dirs):
                                for filename in files:
                                    filepath = os.path.join(root, filename)
                                    if os.path.isfile(filepath) and filepath not in self.matched_files:
                                        try:
                                            result = subprocess.run(
                                                ['yara', self.yara_rule, filepath],
                                                capture_output=True,
                                                text=True
                                            )
                                            if result.stdout:
                                                self.matched_files.add(filepath)
                                                self.log('signature', f"RANSOMWARE DETECTED in {filepath}")
                                                logger.debug(f"Unique YARA match: {filepath}")
                                                if self.enable_sound:
                                                    pass
                                        except (subprocess.CalledProcessError, FileNotFoundError) as e:
                                            logger.debug(f"YARA scan error: {str(e)}")
                    except Exception as e:
                        logger.debug(f"Directory scan error: {str(e)}")

                time.sleep(0.3)
            except Exception as e:
                self.log('behavioral', f"Monitoring error: {str(e)}")
    
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('.', background=COLORS['dark_bg'], foreground=COLORS['text_fg'])
        self.style.configure('TFrame', background=COLORS['dark_bg'])
        self.style.configure('Header.TFrame', background=COLORS['darker_bg'])
        self.style.configure('TLabel', background=COLORS['dark_bg'], foreground=COLORS['text_fg'], font=self.fonts['regular'])
        self.style.configure('Title.TLabel', font=self.fonts['large'], foreground=COLORS['header'])
        self.style.configure('Counter.TLabel', font=self.fonts['bold'], padding=5)
        self.style.configure('Behavioral.TLabel', foreground=COLORS['behavioral'])
        self.style.configure('Anomaly.TLabel', foreground=COLORS['anomaly'])
        self.style.configure('Signature.TLabel', foreground=COLORS['signature'])
        self.style.configure('TButton', background=COLORS['button_bg'], foreground=COLORS['text_fg'], borderwidth=1, relief='raised', font=self.fonts['regular'], padding=5)
        self.style.map('TButton', background=[('active', COLORS['button_active']), ('disabled', COLORS['darker_bg'])], foreground=[('disabled', '#777777')])
        self.style.configure('Status.TLabel', background=COLORS['status_bg'], relief='sunken', anchor='w', padding=5, font=self.fonts['small'])
        self.style.configure('TNotebook', background=COLORS['dark_bg'], borderwidth=0)
        self.style.configure('TNotebook.Tab', background=COLORS['darker_bg'], foreground=COLORS['text_fg'], padding=[10, 5], font=self.fonts['regular'])
        self.style.map('TNotebook.Tab', background=[('selected', COLORS['header']), ('active', COLORS['button_active'])], foreground=[('selected', 'white')])
        
    def create_widgets(self):
        self.main_container = ttk.Frame(self.root)
        self.main_container.grid(row=1, column=0, sticky='nsew', padx=10, pady=(0, 10))
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        header_frame = ttk.Frame(self.root, style='Header.TFrame')
        header_frame.grid(row=0, column=0, sticky='ew', padx=0, pady=0)
        header_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(header_frame, text="Ransomware Detection System", style='Title.TLabel').grid(row=0, column=0, padx=15, pady=5, sticky='w')
        
        counter_frame = ttk.Frame(header_frame)
        counter_frame.grid(row=0, column=1, padx=10, sticky='ew')
        
        self.behavioral_counter = ttk.Label(counter_frame, text="Behavioral: 0", style='Counter.TLabel Behavioral.TLabel')
        self.behavioral_counter.pack(side='left', padx=5)
        
        self.anomaly_counter = ttk.Label(counter_frame, text="Anomaly: 0", style='Counter.TLabel Anomaly.TLabel')
        self.anomaly_counter.pack(side='left', padx=5)
        
        self.signature_counter = ttk.Label(counter_frame, text="Signature: 0", style='Counter.TLabel Signature.TLabel')
        self.signature_counter.pack(side='left', padx=5)
        
        self.view_mode_btn = ttk.Button(header_frame, text="Switch to Vertical View", command=self.toggle_view_mode, style='TButton')
        self.view_mode_btn.grid(row=0, column=2, padx=5, sticky='e')
        
        action_frame = ttk.Frame(header_frame)
        action_frame.grid(row=0, column=3, padx=10, pady=5, sticky='e')
        
        self.save_button = ttk.Button(action_frame, text="Save Logs", command=self.save_logs, style='TButton')
        self.save_button.pack(side='left', padx=5)
        
        self.clear_button = ttk.Button(action_frame, text="Clear Logs", command=self.clear_logs, style='TButton')
        self.clear_button.pack(side='left', padx=5)
        
        button_frame = ttk.Frame(header_frame)
        button_frame.grid(row=0, column=4, padx=10, pady=5, sticky='e')
        
        self.start_button = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring, style='TButton')
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state='disabled', style='TButton')
        self.stop_button.pack(side='left', padx=5)
        
        self.status_var = tk.StringVar(value="Status: Idle")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, style='Status.TLabel')
        self.status_bar.grid(row=2, column=0, sticky='ew', padx=0, pady=0)
        
        self.create_text_widgets()
        
    def create_text_widgets(self):
        self.behavioral_text = scrolledtext.ScrolledText(wrap=tk.WORD, bg=COLORS['panel_bg'], fg=COLORS['text_fg'], insertbackground=COLORS['text_fg'], font=self.fonts['regular'], padx=10, pady=10, highlightthickness=0)
        self.behavioral_text.tag_configure('behavioral', foreground=COLORS['behavioral'])
        
        self.anomaly_text = scrolledtext.ScrolledText(wrap=tk.WORD, bg=COLORS['panel_bg'], fg=COLORS['text_fg'], insertbackground=COLORS['text_fg'], font=self.fonts['regular'], padx=10, pady=10, highlightthickness=0)
        self.anomaly_text.tag_configure('anomaly', foreground=COLORS['anomaly'])
        
        self.signature_text = scrolledtext.ScrolledText(wrap=tk.WORD, bg=COLORS['panel_bg'], fg=COLORS['text_fg'], insertbackground=COLORS['text_fg'], font=self.fonts['regular'], padx=10, pady=10, highlightthickness=0)
        self.signature_text.tag_configure('signature', foreground=COLORS['signature'])
        
    def save_logs(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"ransomware_logs_{timestamp}.txt"
            
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_filename, filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            
            if file_path:
                logs = []
                logs.append("=== Behavioral Logs ===\n")
                logs.append(self.behavioral_text.get("1.0", tk.END))
                logs.append("\n=== Anomaly Logs ===\n")
                logs.append(self.anomaly_text.get("1.0", tk.END))
                logs.append("\n=== Signature Logs ===\n")
                logs.append(self.signature_text.get("1.0", tk.END))
                
                with open(file_path, 'w') as f:
                    f.writelines(logs)
                
                self.status_var.set(f"Status: Logs saved to {file_path}")
                logger.info(f"Logs saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save logs: {str(e)}")
            logger.error(f"Failed to save logs: {str(e)}")
    
    def clear_logs(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all logs?"):
            self.behavioral_text.delete("1.0", tk.END)
            self.anomaly_text.delete("1.0", tk.END)
            self.signature_text.delete("1.0", tk.END)
            self.counter.reset()
            self.matched_files.clear()
            self.update_counters()
            self.status_var.set("Status: Logs cleared")
            logger.info("All logs cleared")
        
    def update_view_mode(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()
        
        if self.view_mode == 'parallel':
            self.main_container.grid_columnconfigure(0, weight=1, uniform='cols')
            self.main_container.grid_columnconfigure(1, weight=1, uniform='cols')
            self.main_container.grid_columnconfigure(2, weight=1, uniform='cols')
            
            behavioral_frame = ttk.Frame(self.main_container)
            behavioral_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
            behavioral_frame.grid_rowconfigure(1, weight=1)
            behavioral_frame.grid_columnconfigure(0, weight=1)
            
            ttk.Label(behavioral_frame, text="Behavioral Monitoring", style='Behavioral.TLabel').grid(row=0, column=0, sticky='w', padx=5, pady=2)
            self.behavioral_text.grid(in_=behavioral_frame, row=1, column=0, sticky='nsew')
            
            anomaly_frame = ttk.Frame(self.main_container)
            anomaly_frame.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
            anomaly_frame.grid_rowconfigure(1, weight=1)
            anomaly_frame.grid_columnconfigure(0, weight=1)
            
            ttk.Label(anomaly_frame, text="Anomaly Detection", style='Anomaly.TLabel').grid(row=0, column=0, sticky='w', padx=5, pady=2)
            self.anomaly_text.grid(in_=anomaly_frame, row=1, column=0, sticky='nsew')
            
            signature_frame = ttk.Frame(self.main_container)
            signature_frame.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)
            signature_frame.grid_rowconfigure(1, weight=1)
            signature_frame.grid_columnconfigure(0, weight=1)
            
            ttk.Label(signature_frame, text="Signature Detection", style='Signature.TLabel').grid(row=0, column=0, sticky='w', padx=5, pady=2)
            self.signature_text.grid(in_=signature_frame, row=1, column=0, sticky='nsew')
            
            self.view_mode_btn.config(text="Switch to Vertical View")
            
        else:
            self.notebook = ttk.Notebook(self.main_container)
            self.notebook.grid(row=0, column=0, sticky='nsew')
            self.notebook.grid_rowconfigure(0, weight=1)
            self.notebook.grid_columnconfigure(0, weight=1)
            
            behavioral_frame = ttk.Frame(self.notebook)
            behavioral_frame.grid_rowconfigure(0, weight=1)
            behavioral_frame.grid_columnconfigure(0, weight=1)
            self.notebook.add(behavioral_frame, text='Behavioral Monitoring')
            self.behavioral_text.grid(in_=behavioral_frame, row=0, column=0, sticky='nsew')
            
            anomaly_frame = ttk.Frame(self.notebook)
            anomaly_frame.grid_rowconfigure(0, weight=1)
            anomaly_frame.grid_columnconfigure(0, weight=1)
            self.notebook.add(anomaly_frame, text='Anomaly Detection')
            self.anomaly_text.grid(in_=anomaly_frame, row=0, column=0, sticky='nsew')
            
            signature_frame = ttk.Frame(self.notebook)
            signature_frame.grid_rowconfigure(0, weight=1)
            signature_frame.grid_columnconfigure(0, weight=1)
            self.notebook.add(signature_frame, text='Signature Detection')
            self.signature_text.grid(in_=signature_frame, row=0, column=0, sticky='nsew')
            
            self.view_mode_btn.config(text="Switch to Parallel View")
        
        self.update_view_layout()
    
    def toggle_view_mode(self):
        self.view_mode = 'vertical' if self.view_mode == 'parallel' else 'parallel'
        self.update_view_mode()
        
    def update_counters(self):
        self.behavioral_counter.config(text=f"Behavioral: {self.counter.get_count('behavioral')}")
        self.anomaly_counter.config(text=f"Anomaly: {self.counter.get_count('anomaly')}")
        self.signature_counter.config(text=f"Signature: {self.counter.get_count('signature')}")
        
    def log(self, detection_type, message):
        text_widget = {
            'behavioral': self.behavioral_text,
            'anomaly': self.anomaly_text,
            'signature': self.signature_text
        }.get(detection_type, self.behavioral_text)
        
        text_widget.insert(tk.END, f"{time.ctime()}: {message}\n")
        text_widget.tag_add(detection_type, 'end-1c linestart', 'end-1c lineend')
        text_widget.see(tk.END)
        
        self.counter.increment(detection_type)
        self.update_counters()
        logger.info(f"[{detection_type.upper()}] {message}")
        
    def start_monitoring(self):
        if not self.running:
            self.running = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.status_var.set(f"Status: Monitoring {len(self.monitored_dirs)} directories")
            self.matched_files.clear()
            self.log('behavioral', "Starting monitoring...")
            
            self.detector = RansomwareDetector(self, self.monitored_dirs, self.excluded_dirs)
            self.detector.start_monitoring()
            
            Thread(target=self.monitor_loop, daemon=True).start()
            
    def stop_monitoring(self):
        if self.running:
            self.running = False
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.status_var.set("Status: Idle")
            self.log('behavioral', "Monitoring stopped.")
            self.matched_files.clear()
            
            if self.detector:
                self.detector.stop_monitoring()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=10)
        root.option_add("*Font", default_font)
        app = RansomwareStyledGUI(root)
        root.mainloop()
    except Exception as e:
        logger.error(f"Application failed: {str(e)}")
        messagebox.showerror("Error", f"Application failed: {str(e)}")