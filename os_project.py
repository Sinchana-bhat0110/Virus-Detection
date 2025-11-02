import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os

# Suspicious patterns to detect
HEURISTIC_PATTERNS = ["eval(", "exec(", "base64.b64decode", "import os", "subprocess", "rm -rf", "system("]

def compute_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def heuristics_scan(file_path):
    matches = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()
            for pattern in HEURISTIC_PATTERNS:
                if pattern in content:
                    matches.append(pattern)
    except Exception as e:
        matches.append(f"Error reading file: {e}")
    return matches

def scan_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    sha256 = compute_sha256(file_path)
    matches = heuristics_scan(file_path)

    result_text = f"File: {os.path.basename(file_path)}\nSHA256: {sha256}\n\n"
    if matches:
        result_text += "⚠ Suspicious patterns found:\n" + "\n".join(f"- {m}" for m in matches)
        result_label.config(bg="#fff3cd", fg="#856404")
    else:
        result_text += "✅ No suspicious patterns found.\nStatus: Clean"
        result_label.config(bg="#d4edda", fg="#155724")

    result_label.config(text=result_text)

# GUI setup
root = tk.Tk()
root.title("Sinchana Antivirus")
root.geometry("500x400")
root.configure(bg="#f0f8ff")

title = tk.Label(root, text="Sinchana Antivirus", font=("Arial", 18, "bold"), bg="#f0f8ff", fg="#333")
title.pack(pady=20)

scan_btn = tk.Button(root, text="Upload & Scan File", command=scan_file, font=("Arial", 12), bg="#ff6f61", fg="white", padx=10, pady=5)
scan_btn.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 10), bg="#f0f8ff", justify="left", wraplength=450)
result_label.pack(pady=20)

root.mainloop()