import tkinter as tk
from tkinter import messagebox
import requests
import socket


def check_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            result_label.config(text="URL is valid", fg="green")
        else:
            result_label.config(text=f"URL returned status code: {response.status_code}", fg="red")
    except:
        result_label.config(text="Error accessing URL", fg="red")


def scan_vulnerabilities(url):
    try:
        # Check if the URL is accessible
        response = requests.get(url)
        if response.status_code != 200:
            messagebox.showerror("Error", f"URL returned status code {response.status_code}. Exiting...")
            return

        # Check for directory traversal vulnerability
        path_traversal_url = url + '/../../../etc/passwd'
        path_traversal_response = requests.get(path_traversal_url)
        if path_traversal_response.status_code == 200:
            messagebox.showerror("Vulnerability", "Directory traversal vulnerability detected.")
            return
        
        # Check for SQL injection vulnerability
        sql_injection_url = url + "?id=1' OR '1'='1"
        sql_injection_response = requests.get(sql_injection_url)
        if sql_injection_response.status_code == 200:
            messagebox.showerror("Vulnerability", "SQL injection vulnerability detected.")
            return

        messagebox.showinfo("Scan complete", "No vulnerabilities detected.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def run_scan():
    url = entry.get()
    scan_vulnerabilities(url)


def get_ip(url):
    try:
        # Resolve the hostname to an IP address
        ip = socket.gethostbyname(url)
        messagebox.showinfo("IP Address", f"The IP address of {url} is {ip}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def run_lookup():
    url = entry2.get()
    get_ip(url)


root = tk.Tk()
root.geometry('900x700')
root.configure(background='black')
root.title("Solum Vulnerabilities Scanner")

frame1 = tk.Frame(root, bg='grey')
frame2 = tk.Frame(root, bg='grey')
frame3 = tk.Frame(root, bg='grey')

label = tk.Label(root, text="Validate URL", bg='grey')
url_label = tk.Label(frame1, text="Enter URL :")
url_entry = tk.Entry(frame1)
result_label = tk.Label(frame1, text="")
check_button = tk.Button(frame1, text="Check", command=lambda: check_url(url_entry.get()))

label2 = tk.Label(root, text="Scan Vulnerabilities", bg='grey')
label3 = tk.Label(frame2, text="Enter URL :")
entry = tk.Entry(frame2)
scan_button = tk.Button(frame2, text="Scan", command=run_scan)

label5 = tk.Label(root, text="WhoIs", bg='grey')
label4 = tk.Label(frame3, text="Enter URL:")
entry2 = tk.Entry(frame3)
lookup_button = tk.Button(frame3, text="Lookup", command=run_lookup)

frame1.grid(row=1, column=0, pady=20, padx=60)
frame2.grid(row=1, column=1, pady=20, padx=60)
frame3.grid(row=3, column=0, pady=20, padx=60)

label.grid(row=0, column=0, padx=10, pady=10)
url_label.grid(row=1, column=0, padx=10, pady=10)
url_entry.grid(row=1, column=1, padx=10, pady=10)
check_button.grid(row=2, columnspan=2, padx=10, pady=10)
result_label.grid(row=3, columnspan=2, padx=10, pady=10)

label2.grid(row=0, column=1, padx=10, pady=10)
label3.grid(row=1, column=0, padx=10, pady=10)
entry.grid(row=1, column=1, padx=10, pady=10)
scan_button.grid(row=2, column=1, padx=10, pady=10)

label5.grid(row=2, column=0, padx=10, pady=10)
label4.grid(row=0, column=0, padx=10, pady=10)
entry2.grid(row=0, column=1, padx=10, pady=10)
lookup_button.grid(row=1, column=2, padx=10, pady=10)

root.mainloop()