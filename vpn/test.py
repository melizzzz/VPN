import tkinter as tk
import wmi
import pythoncom

def set_tap_ip(ip, mask):
    # Nécessaire car WMI a besoin de pythoncom.Init
    pythoncom.CoInitialize()
    c = wmi.WMI()
    nic_configs = c.Win32_NetworkAdapterConfiguration(IPEnabled=True)
    for nic in nic_configs:
        # Vérifie si c'est l'interface TAP
        if "TAP-Windows Adapter V9" in nic.Description:
            # Assigner l'adresse IP statique
            res_ip = nic.EnableStatic(IPAddress=[ip], SubnetMask=[mask])
            if res_ip[0] == 0:
                status_label.config(text=f"L'adresse {ip} a été assignée avec succès.")
            else:
                status_label.config(text=f"Échec lors de l'attribution. Code : {res_ip[0]}")
            break
    else:
        status_label.config(text="Interface TAP non trouvée.")

def apply_settings():
    ip = ip_entry.get()
    mask = mask_entry.get()
    if ip and mask:
        set_tap_ip(ip, mask)
    else:
        status_label.config(text="Veuillez remplir les deux champs IP et Masque.")

# Création de la fenêtre Tkinter
root = tk.Tk()
root.title("Contrôleur d'Adresse IP TAP")

tk.Label(root, text="Adresse IP :").grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Masque :").grid(row=1, column=0, padx=5, pady=5)
mask_entry = tk.Entry(root)
mask_entry.grid(row=1, column=1, padx=5, pady=5)

apply_button = tk.Button(root, text="Appliquer", command=apply_settings)
apply_button.grid(row=2, column=0, columnspan=2, pady=10)

status_label = tk.Label(root, text="")
status_label.grid(row=3, column=0, columnspan=2)

root.mainloop()
