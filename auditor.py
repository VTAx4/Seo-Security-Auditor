import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import threading
import logic

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SEO & Security Auditor")
        self.geometry("700x550")
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- Input Frame ---
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter website URL and press Enter...")
        self.url_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.url_entry.bind("<Return>", self.on_enter_key)
        
        self.analyze_button = ctk.CTkButton(self.input_frame, text="Analyze", command=self.start_analysis, fg_color="#00c753", hover_color="#009e42")
        self.analyze_button.grid(row=0, column=1, padx=10, pady=10)
        
        # --- Score Frame ---
        self.score_frame = ctk.CTkFrame(self)
        self.score_frame.grid(row=1, column=0, padx=20, pady=0, sticky="ew")
        self.score_frame.grid_columnconfigure((0, 1), weight=1)
        
        self.security_score_label = ctk.CTkLabel(self.score_frame, text="Security Score: - / 100", font=ctk.CTkFont(size=16, weight="bold"))
        self.security_score_label.grid(row=0, column=0, padx=10, pady=10)
        
        self.seo_score_label = ctk.CTkLabel(self.score_frame, text="SEO Score: - / 100", font=ctk.CTkFont(size=16, weight="bold"))
        self.seo_score_label.grid(row=0, column=1, padx=10, pady=10)

        # --- Results Box ---
        self.results_box = ctk.CTkTextbox(self, wrap=tk.WORD)
        self.results_box.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

        # --- Save Button ---
        self.save_button = ctk.CTkButton(self, text="Save Report", command=self.save_report, state="disabled")
        self.save_button.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
    def on_enter_key(self, event):
        self.start_analysis()

    def start_analysis(self):
        target_url = self.url_entry.get()
        if not target_url:
            self.results_box.delete('1.0', ctk.END)
            self.results_box.insert(ctk.END, "Error: Please enter a URL.")
            return
        
        self.analyze_button.configure(state="disabled", text="Analyzing...")
        self.save_button.configure(state="disabled")
        self.results_box.delete('1.0', ctk.END)
        self.results_box.insert('1.0', f"Analyzing {target_url}...\n\n")
        
        thread = threading.Thread(target=self.run_analysis_in_thread, args=(target_url,))
        thread.start()

    def run_analysis_in_thread(self, url):
        report, security_score, seo_score = logic.analyze_website(url)
        
        self.results_box.insert(ctk.END, report)
        self.security_score_label.configure(text=f"Security Score: {security_score} / 100")
        self.seo_score_label.configure(text=f"SEO Score: {seo_score} / 100")
        self.analyze_button.configure(state="normal", text="Analyze")
        self.save_button.configure(state="normal")
        
    def save_report(self):
        report_content = self.results_box.get("1.0", ctk.END)
        score_header = f"{self.security_score_label.cget('text')} | {self.seo_score_label.cget('text')}\n\n"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Report As..."
        )
        if not file_path:
            return
            
        with open(file_path, "w", encoding="utf-8") as file:
            file.write("SEO & Security Audit Report\n")
            file.write("==========================\n\n")
            file.write(score_header)
            file.write(report_content)

if __name__ == "__main__":
    app = App()
    app.mainloop()