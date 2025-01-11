import subprocess
import os
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

class WebFuzzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Application Fuzzer Tool")
        self.root.geometry("850x750")
        self.root.configure(bg="#f0f0f0")

        self.fuzzer_results = []
        
        # Title Label
        title_label = tk.Label(root, text="Web Application Fuzzer Tool", font=("Arial", 20, "bold"), bg="#4CAF50", fg="white", pady=10)
        title_label.pack(fill=tk.X)

        # Website input
        self.target_url = tk.StringVar()
        url_frame = tk.Frame(root, bg="#f0f0f0")
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

        tool_frame = tk.Frame(root, bg="#f0f0f0")
        tool_label = tk.Label(tool_frame, text="Select Tools to Run:", font=("Arial", 16, "bold"), bg="#f0f0f0", pady=5)
        tool_label.pack(anchor='w')

        tk.Checkbutton(tool_frame, text="Subdomain Enumeration (Amass)", variable=self.amass_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Vulnerability Scanning (OWASP ZAP)", variable=self.zap_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="SQL Injection Detection (Sqlmap)", variable=self.sqlmap_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Fuzzing (Wfuzz)", variable=self.wfuzz_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Network Scanning (Nmap)", variable=self.nmap_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Exploitation (Metasploit)", variable=self.metasploit_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="API Testing (Postman)", variable=self.postman_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Dependency Scanning (Snyk)", variable=self.snyk_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Network Vulnerability Scanning (OpenVAS)", variable=self.openvas_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Web App Security (Arachni)", variable=self.arachni_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tk.Checkbutton(tool_frame, text="Vulnerability Testing (OWASP Juice Shop)", variable=self.juiceshop_var, bg="#f0f0f0", font=("Arial", 12)).pack(anchor='w')
        tool_frame.pack(pady=10)

        # Action buttons
        action_frame = tk.Frame(root, bg="#f0f0f0")
        self.run_button = tk.Button(action_frame, text="Run Selected Tools", command=self.run_selected_tools, bg="#4CAF50", fg="white", font=("Arial", 14), width=20)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(action_frame, text="Clear Results", command=self.clear_results, bg="#FF9800", fg="white", font=("Arial", 14), width=15)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.reset_button = tk.Button(action_frame, text="Reset Scans", command=self.reset_scans, bg="#F44336", fg="white", font=("Arial", 14), width=15)
        self.reset_button.pack(side=tk.LEFT, padx=5)

        action_frame.pack(pady=10)

        # Tool status tracking
        self.tool_progress = {}
        self.tool_labels = {}
        self.tool_progress_bars = {}

        # Result area
        result_label = tk.Label(root, text="Results:", bg="#f0f0f0", font=("Arial", 14, "bold"))
        result_label.pack(pady=5)
        self.result_text = tk.Text(root, height=10, width=90, state='disabled', wrap="word", font=("Arial", 12))
        self.result_text.pack(pady=10)

        # Save report button
        self.report_button = tk.Button(root, text="Generate Report", command=self.generate_report, state='disabled', bg="#2196f3", fg="white", font=("Arial", 14), width=20)
        self.report_button.pack(pady=5)

    def setup_tool_progress(self, tool_name):
        frame = tk.Frame(self.root, bg="#f0f0f0")
        label = tk.Label(frame, text=f"{tool_name}", bg="#f0f0f0", font=("Arial", 12))
        label.pack(side=tk.LEFT, padx=5)
        progress_bar = ttk.Progressbar(frame, orient="horizontal", length=250, mode="determinate")
        progress_bar.pack(side=tk.LEFT, padx=10)
        tick_label = tk.Label(frame, text="", bg="#f0f0f0", font=("Arial", 16))
        tick_label.pack(side=tk.LEFT, padx=5)

        self.tool_progress[tool_name] = 0
        self.tool_labels[tool_name] = tick_label
        self.tool_progress_bars[tool_name] = progress_bar

        frame.pack(pady=5)

    def update_progress(self, tool_name, value):
        self.tool_progress_bars[tool_name]["value"] = value
        if value >= 100:
            self.tool_labels[tool_name].config(text="✔", fg="green")

    def mark_vulnerability(self, tool_name, vulnerability_message, solution):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"[{tool_name}] VULNERABILITY FOUND!\n")
        self.result_text.insert(tk.END, f"Vulnerability: {vulnerability_message}\n")
        self.result_text.insert(tk.END, f"Suggested Solution: {solution}\n\n")
        self.result_text.config(state='disabled')

    def run_selected_tools(self):
        self.run_button.config(state='disabled')
        self.report_button.config(state='disabled')
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)

        selected_tools = []
        if self.amass_var.get():
            selected_tools.append(("Amass", self.run_amass))
        if self.zap_var.get():
            selected_tools.append(("OWASP ZAP", self.run_owasp_zap))
        if self.sqlmap_var.get():
            selected_tools.append(("Sqlmap", self.run_sqlmap))
        if self.wfuzz_var.get():
            selected_tools.append(("Wfuzz", self.run_wfuzz))
        if self.nmap_var.get():
            selected_tools.append(("Nmap", self.run_nmap))
        if self.metasploit_var.get():
            selected_tools.append(("Metasploit", self.run_metasploit))
        if self.postman_var.get():
            selected_tools.append(("Postman", self.run_postman))
        if self.snyk_var.get():
            selected_tools.append(("Snyk", self.run_snyk))
        if self.openvas_var.get():
            selected_tools.append(("OpenVAS", self.run_openvas))
        if self.arachni_var.get():
            selected_tools.append(("Arachni", self.run_arachni))
        if self.juiceshop_var.get():
            selected_tools.append(("OWASP Juice Shop", self.run_juice_shop))

        for tool_name, tool_function in selected_tools:
            self.setup_tool_progress(tool_name)

        # Run each tool and update the progress
        for i, (tool_name, tool_function) in enumerate(selected_tools):
            tool_function(tool_name)
            self.update_progress(tool_name, 100)

        self.result_text.config(state='disabled')
        self.run_button.config(state='normal')
        self.report_button.config(state='normal')

    def append_result(self, tool_name, output):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"{tool_name} Results:\n{output}\n\n")
        self.result_text.config(state='disabled')
        self.fuzzer_results.append({'Module': tool_name, 'Output': output})

    def clear_results(self):
        """Clear all the scan results and reset the result text box."""
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        self.fuzzer_results = []
        messagebox.showinfo("Info", "Results have been cleared.")

    def reset_scans(self):
        """Reset the progress of all scans and clear results."""
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

        for tool_name in self.tool_progress_bars:
            self.tool_progress_bars[tool_name]["value"] = 0
            self.tool_labels[tool_name].config(text="")
        messagebox.showinfo("Info", "All scans have been reset.")

    def run_amass(self, tool_name):
        target_url = self.target_url.get()
        try:
            result = subprocess.run(['amass', 'enum', '-d', target_url], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Amass is not installed or not in PATH.")

    def run_owasp_zap(self, tool_name):
        target_url = self.target_url.get()
        try:
            result = subprocess.run(['zap-cli', 'quick-scan', target_url], capture_output=True, text=True)
            if "vulnerability" in result.stdout.lower():
                self.mark_vulnerability(tool_name, "OWASP ZAP detected vulnerabilities", "Patch your web application and apply secure coding practices.")
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "OWASP ZAP is not installed or not in PATH.")

    def run_sqlmap(self, tool_name):
        target_url = self.target_url.get()
        try:
            result = subprocess.run(['sqlmap', '-u', target_url], capture_output=True, text=True)
            if "vulnerable" in result.stdout.lower():
                self.mark_vulnerability(tool_name, "SQL Injection vulnerability found", "Sanitize user inputs and use parameterized queries.")
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Sqlmap is not installed or not in PATH.")

    def run_wfuzz(self, tool_name):
        target_url = self.target_url.get()
        if not os.path.exists('wordlist.txt'):
            messagebox.showerror("Error", "wordlist.txt not found.")
            return
        try:
            result = subprocess.run(['wfuzz', '-c', '-z', 'file,wordlist.txt', f'{target_url}/FUZZ'], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Wfuzz is not installed or not in PATH.")

    def run_nmap(self, tool_name):
        target_url = self.target_url.get()
        try:
            result = subprocess.run(['nmap', '-sS', target_url], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Nmap is not installed or not in PATH.")

    def run_metasploit(self, tool_name):
        try:
            result = subprocess.run(['msfconsole', '-q', '-x', 'use exploit/multi/handler'], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Metasploit is not installed or not in PATH.")

    def run_postman(self, tool_name):
        try:
            result = subprocess.run(['postman', 'run', 'api_collection.json'], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Postman is not installed or not in PATH.")

    def run_snyk(self, tool_name):
        try:
            result = subprocess.run(['snyk', 'test'], capture_output=True, text=True)
            if "vulnerable" in result.stdout.lower():
                self.mark_vulnerability(tool_name, "Dependency vulnerability found", "Update dependencies to the latest version or patch the security issue.")
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Snyk is not installed or not in PATH.")

    def run_openvas(self, tool_name):
        try:
            result = subprocess.run(['openvas', '--scan', 'target'], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "OpenVAS is not installed or not in PATH.")

    def run_arachni(self, tool_name):
        try:
            result = subprocess.run(['arachni', '--scan', 'target'], capture_output=True, text=True)
            if "vulnerability" in result.stdout.lower():
                self.mark_vulnerability(tool_name, "Arachni found vulnerabilities", "Follow security practices for web app security.")
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "Arachni is not installed or not in PATH.")

    def run_juice_shop(self, tool_name):
        try:
            result = subprocess.run(['juice-shop', 'test'], capture_output=True, text=True)
            self.append_result(tool_name, result.stdout)
        except FileNotFoundError:
            messagebox.showerror("Error", "OWASP Juice Shop is not installed or not in PATH.")

    def generate_report(self):
        if not self.fuzzer_results:
            messagebox.showwarning("Warning", "No scan results available to generate a report.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not file_path:
            return

        try:
            with open(file_path, 'w') as report_file:
                for result in self.fuzzer_results:
                    report_file.write(f"{result}\n")
            messagebox.showinfo("Success", f"Report generated successfully at: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = WebFuzzer(root)
    root.mainloop()