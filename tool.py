import subprocess
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time
import json

class WebApplicationFuzzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Application Fuzzer Tool")
        self.root.geometry("850x850")
        self.root.configure(bg="#f0f0f0")

        self.fuzzer_results = []
        self.suggestions = {
            "Amass": "Suggestion: Review DNS records and subdomain structure for potential vulnerabilities.",
            "OWASP ZAP": "Suggestion: Inspect identified vulnerabilities and prioritize fixing based on severity.",
            "Sqlmap": "Suggestion: Ensure input fields are properly sanitized to avoid SQL injections.",
            "Wfuzz": "Suggestion: Implement rate-limiting to prevent fuzzing attacks.",
            "Nmap": "Suggestion: Restrict open ports and services exposed to the internet.",
            "Metasploit": "Suggestion: Patch identified exploits and update vulnerable software.",
            "Postman": "Suggestion: Validate API inputs and authenticate requests securely.",
            "Snyk": "Suggestion: Update outdated dependencies and review security advisories.",
            "OpenVAS": "Suggestion: Follow best practices for securing network services.",
            "Arachni": "Suggestion: Fix Cross-Site Scripting (XSS) issues identified in the scan.",
            "OWASP Juice Shop": "Suggestion: Address common vulnerabilities such as weak authentication mechanisms."
        }

        # Split the window into two sections
        self.main_div = tk.Frame(self.root)
        self.main_div.pack(fill=tk.BOTH, expand=True)

        self.left_div = tk.Frame(self.main_div, bg="#f0f0f0", width=400)
        self.left_div.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10)

        self.right_div = tk.Frame(self.main_div, bg="#f0f0f0", width=400)
        self.right_div.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)

        # Title Label
        title_label = tk.Label(self.left_div, text="Web Application Fuzzer Tool", font=("Arial", 20, "bold"), bg="#4CAF50", fg="white", pady=10)
        title_label.pack(fill=tk.X)

        # Website input
        self.target_url = tk.StringVar()
        url_frame = tk.Frame(self.left_div, bg="#f0f0f0")
        tk.Label(url_frame, text="Target Website:", font=("Arial", 14), bg="#f0f0f0").pack(side=tk.LEFT, padx=10)
        self.url_entry = tk.Entry(url_frame, textvariable=self.target_url, width=50, font=("Arial", 14))
        self.url_entry.pack(side=tk.LEFT, padx=10)
        self.url_entry.insert(0, "http://localhost")  # Default to localhost
        url_frame.pack(pady=10)

        # Tool selection area
        self.amass_var = tk.BooleanVar()
        self.zap_var = tk.BooleanVar()
        self.sqlmap_var = tk.BooleanVar()
        self.wfuzz_var = tk.BooleanVar()
        self.nmap_var = tk.BooleanVar()
        self.metasploit_var = tk.BooleanVar()
        self.postman_var = tk.BooleanVar()
        self.snyk_var = tk.BooleanVar()
        self.openvas_var = tk.BooleanVar()
        self.arachni_var = tk.BooleanVar()
        self.juiceshop_var = tk.BooleanVar()

        tool_div = tk.Frame(self.left_div, bg="#f0f0f0")
        tool_label = tk.Label(tool_div, text="Select Tools to Run:", font=("Arial", 16, "bold"), bg="#f0f0f0", pady=5)
        tool_label.pack(anchor='w')

        tk.Checkbutton(tool_div, text="Subdomain Enumeration (Amass)", variable=self.amass_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Vulnerability Scanning (OWASP ZAP)", variable=self.zap_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="SQL Injection Detection (Sqlmap)", variable=self.sqlmap_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Fuzzing (Wfuzz)", variable=self.wfuzz_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Network Scanning (Nmap)", variable=self.nmap_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Exploitation (Metasploit)", variable=self.metasploit_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="API Testing (Postman)", variable=self.postman_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Dependency Scanning (Snyk)", variable=self.snyk_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Network Vulnerability Scanning (OpenVAS)", variable=self.openvas_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Web App Security (Arachni)", variable=self.arachni_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_div, text="Vulnerability Testing (OWASP Juice Shop)", variable=self.juiceshop_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tool_div.pack(pady=10)

        # Action buttons
        action_frame = tk.Frame(self.left_div, bg="#f0f0f0")
        self.run_button = tk.Button(action_frame, text="Run Selected Tools", command=self.run_selected_tools, bg="#4CAF50", fg="white", font=("Arial", 14), width=20)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(action_frame, text="Clear Results", command=self.clear_results, bg="#FF9800", fg="white", font=("Arial", 14), width=15)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.reset_button = tk.Button(action_frame, text="Reset Scans", command=self.reset_scans, bg="#F44336", fg="white", font=("Arial", 14), width=15)
        self.reset_button.pack(side=tk.LEFT, padx=5)

        action_frame.pack(pady=10)

        # Result area
        result_label = tk.Label(self.left_div, text="Results:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        result_label.pack(pady=5)
        self.result_text = tk.Text(self.left_div, height=10, width=50, state='disabled', wrap="word", font=("Arial", 12))
        self.result_text.pack(pady=10)

        # Save report button
        self.report_button = tk.Button(self.left_div, text="Generate Report", command=self.generate_report, state='disabled', bg="#2196f3", fg="white", font=("Arial", 14), width=20)
        self.report_button.pack(pady=5)

        # Right side for progress bar and tick mark
        self.tool_progress = {}
        self.tool_labels = {}
        self.tool_progress_bars = {}

        # Suggestion box below progress bars
        self.suggestion_label = tk.Label(self.right_div, text="Suggestions:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        self.suggestion_label.pack(pady=10)

        self.suggestion_text = tk.Text(self.right_div, height=10, width=50, state='normal', wrap="word", font=("Arial", 12))
        self.suggestion_text.pack(pady=10)

    def setup_tool_progress(self, tool_name):
        frame = tk.Frame(self.right_div, bg="#f0f0f0")
        label = tk.Label(frame, text=f"{tool_name}", bg="#f0f0f0", font=("Arial", 12, "bold"), fg="#007BFF")  # Blue color
        label.pack(side=tk.LEFT, padx=5)
        progress_bar = ttk.Progressbar(frame, orient="horizontal", length=250, mode="determinate")
        progress_bar.pack(side=tk.LEFT, padx=10)
        tick_label = tk.Label(frame, text="", bg="#f0f0f0", font=("Arial", 12))
        tick_label.pack(side=tk.LEFT, padx=5)

        self.tool_progress[tool_name] = 0
        self.tool_labels[tool_name] = tick_label
        self.tool_progress_bars[tool_name] = progress_bar

        frame.pack(pady=5)

    def run_selected_tools(self):
        tools_to_run = []
        if self.amass_var.get():
            tools_to_run.append("Amass")
        if self.zap_var.get():
            tools_to_run.append("OWASP ZAP")
        if self.sqlmap_var.get():
            tools_to_run.append("Sqlmap")
        if self.wfuzz_var.get():
            tools_to_run.append("Wfuzz")
        if self.nmap_var.get():
            tools_to_run.append("Nmap")
        if self.metasploit_var.get():
            tools_to_run.append("Metasploit")
        if self.postman_var.get():
            tools_to_run.append("Postman")
        if self.snyk_var.get():
            tools_to_run.append("Snyk")
        if self.openvas_var.get():
            tools_to_run.append("OpenVAS")
        if self.arachni_var.get():
            tools_to_run.append("Arachni")
        if self.juiceshop_var.get():
            tools_to_run.append("OWASP Juice Shop")

        if tools_to_run:
            for tool in tools_to_run:
                self.setup_tool_progress(tool)
            self.run_button.config(state='disabled')
            self.result_text.config(state='normal')
            self.result_text.delete(1.0, tk.END)
            self.result_text.config(state='disabled')
            self.suggestion_text.config(state='normal')
            self.suggestion_text.delete(1.0, tk.END)
            self.suggestion_text.config(state='disabled')

            self.root.after(1000, self.run_scans, tools_to_run)

    def run_scans(self, tools):
        if not tools:
            self.run_button.config(state='normal')
            self.report_button.config(state='normal')
            return

        tool = tools[0]
        self.update_progress(tool)
        self.root.after(1000, self.run_scans, tools[1:])

    def update_progress(self, tool):
        for i in range(101):
            self.root.update_idletasks()
            self.tool_progress_bars[tool].config(value=i)
            self.tool_progress[tool] = i
            self.result_text.config(state='normal')
            self.result_text.insert(tk.END, f"{tool}: {i}% completed\n")
            self.result_text.see(tk.END)  # Scroll to the bottom
            self.result_text.config(state='disabled')

            if i == 100:
                self.tool_labels[tool].config(text="✓")
                self.result_text.config(state='normal')
                self.result_text.insert(tk.END, f"{tool} scan completed.\n\n")
                self.result_text.see(tk.END)  # Scroll to the bottom
                self.result_text.config(state='disabled')
                self.suggestion_text.config(state='normal')
                self.suggestion_text.insert(tk.END, f"\n{tool}: {self.suggestions[tool]}\n")
                self.suggestion_text.config(state='disabled')

            time.sleep(0.02)


    def clear_results(self):
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')

    def reset_scans(self):
        self.clear_results()
        self.amass_var.set(False)
        self.zap_var.set(False)
        self.sqlmap_var.set(False)
        self.wfuzz_var.set(False)
        self.nmap_var.set(False)
        self.metasploit_var.set(False)
        self.postman_var.set(False)
        self.snyk_var.set(False)
        self.openvas_var.set(False)
        self.arachni_var.set(False)
        self.juiceshop_var.set(False)

        # Reset progress bars and labels
        for tool in self.tool_progress_bars:
            self.tool_progress_bars[tool].config(value=0)
            self.tool_labels[tool].config(text="")
            # self.tool_progress_bars[tool].destroy()
            # self.tool_labels[tool].destroy()
        
        # Clear the suggestion box as well
        self.suggestion_text.config(state='normal')
        self.suggestion_text.delete(1.0, tk.END)
        self.suggestion_text.config(state='disabled')


    def generate_report(self):
        report_data = {
            "target_url": self.target_url.get(),
            "tools_used": [tool for tool, progress in self.tool_progress.items() if progress == 100],
            "results": self.result_text.get(1.0, tk.END).strip(),
            "suggestions": self.suggestion_text.get(1.0, tk.END).strip()
        }

        report_file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if report_file:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=4)

            messagebox.showinfo("Report Saved", "Scan report saved successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebApplicationFuzzerGUI(root)
    root.mainloop()
