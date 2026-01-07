import tkinter as tk
from PIL import Image, ImageTk
from io import BytesIO
from tkinter import ttk, messagebox, filedialog, font
import requests, threading, csv, time
from ttkthemes import ThemedTk
from datetime import datetime, timezone, timedelta
import re, sys, os, base64

showDefaultTab = True

def load_icon_from_web(url, size=(32, 32)):
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to download icon.")
    img_data = response.content
    img = Image.open(BytesIO(img_data)).resize(size)
    return ImageTk.PhotoImage(img)

class ScrollableFrame(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

        canvas = tk.Canvas(self, borderwidth=0, bg="#eaeaf2")
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg="#eaeaf2")

        self.window_id = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        # Configure scroll region
        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # Resize the inner frame to match the canvas width
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(self.window_id, width=e.width))

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind mousewheel events
        self.bind_mousewheel(canvas)

    def bind_mousewheel(self, target):
        # Windows & Mac
        target.bind_all("<MouseWheel>", lambda e: target.yview_scroll(int(-1 * (e.delta / 120)), "units"))
        # Linux
        target.bind_all("<Button-4>", lambda e: target.yview_scroll(-1, "units"))
        target.bind_all("<Button-5>", lambda e: target.yview_scroll(1, "units"))

def get_org_details():
    # Placeholder for fetching organization details
    client_id = client_id_entry.get().strip()
    client_secret = client_secret_entry.get().strip()

    if not client_id or not client_secret:
        messagebox.showerror("Missing Credentials", "Client ID and Client Secret are required.")
        return
    
    test_oauth_credentials_btn.config(text=" Loading... ", font=("Segoe UI", 8, "italic"))
    test_oauth_credentials_btn.config(state="disabled")
    
    def task():
        try:
            # --- OAuth Token ---
            auth_url = "https://login.mypurecloud.jp/oauth/token"
            auth_header = base64.b64encode(
                f"{client_id}:{client_secret}".encode()
            ).decode()

            token_response = requests.post(
                auth_url,
                headers={
                    "Authorization": f"Basic {auth_header}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={"grant_type": "client_credentials"},
                timeout=15
            )
            token_response.raise_for_status()
            access_token = token_response.json()["access_token"]

            # --- Get Org Details ---
            org_response = requests.get(
                "https://api.mypurecloud.jp/api/v2/organizations/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=15
            )
            org_response.raise_for_status()
            org_data = org_response.json()

            # --- Update UI safely ---
            root.after(0, lambda: update_org_ui(org_data))

        except requests.exceptions.RequestException as e:
            root.after(0, lambda: messagebox.showerror("API Error", str(e)))
            root.after(0, show_organization_info_frame.forget)
        finally:
            root.after(0, stop_loading)

    threading.Thread(target=task, daemon=True).start()
    
def update_org_ui(org_data):
    org_id_value.config(text=org_data.get("id", "N/A"))
    org_name_value.config(text=org_data.get("name", "N/A"))
    org_domain_value.config(text=org_data.get("domain", "N/A"))

    show_organization_info_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))

def stop_loading():
    test_oauth_credentials_btn.config(text=" Authenticate ", font=("Segoe UI", 8))
    test_oauth_credentials_btn.config(state="normal")
    
def show_home():
    home_parent_frame.pack(fill="both", expand=True)
    user_management_parent_frame.pack_forget()
    settings_parent_frame.pack_forget()

    menu_btn_home.config(bg="#273F4F", font=("Segoe UI", 10, "bold"))
    menu_btn_user_management.config(bg="#343d40", font=("Segoe UI", 10))
    menu_btn_settings.config(bg="#343d40", font=("Segoe UI", 10))

def show_user_management():

    if showDefaultTab == True:
        home_parent_frame.pack_forget()
        user_management_parent_frame.pack(fill="both", expand=True)
        settings_parent_frame.pack_forget()
        user_management_agent_performance_parent_frame.pack(fill="both", expand=True, padx=5, pady=5)
        showDefaultTab == False
    
    else:
        home_parent_frame.pack_forget()
        user_management_parent_frame.pack(fill="both", expand=True)
        settings_parent_frame.pack_forget()

    menu_btn_home.config(bg="#343d40", font=("Segoe UI", 10))
    menu_btn_user_management.config(bg="#273F4F", font=("Segoe UI", 10, "bold"))
    menu_btn_settings.config(bg="#343d40", font=("Segoe UI", 10))

def show_settings():
    home_parent_frame.pack_forget()
    user_management_parent_frame.pack_forget()
    settings_parent_frame.pack(fill="both", expand=True)

    menu_btn_home.config(bg="#343d40", font=("Segoe UI", 10))
    menu_btn_user_management.config(bg="#343d40", font=("Segoe UI", 10))
    menu_btn_settings.config(bg="#273F4F", font=("Segoe UI", 10, "bold"))

def setup_treeview(parent, columns):
    # Destroy old Treeview if it exists
    global user_tree
    for widget in parent.winfo_children():
        widget.destroy()

    # Create new Treeview
    tree = ttk.Treeview(parent, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=100, anchor="center")

    tree.pack(fill="both", expand=True, padx=5, pady=5)
    tree.bind("<<TreeviewSelect>>", on_tree_select)
    user_tree = tree

def on_tree_select(event):
    selected_item = user_tree.focus()

    if selected_item:
        values = user_tree.item(selected_item, "values")
        user_tree_output_lbl.config(text=f"Selected: {values}")

def show_checkbox():
    checkbox_frame.pack(anchor="n", padx=5, pady=5)
    add_column_btn.config(state="disabled")
    separator.config(bg="grey")

def hide_listbox():
    selected = [item for item, var in checkbox_var.items() if var.get()]
    
    if selected:
        setup_treeview(user_body_frame, selected)

    checkbox_frame.pack_forget()
    add_column_btn.config(state="active")
    separator.config(bg="#eaeaf2")

def get_selected_columns():
    return [key for key, var in checkbox_var.items() if var.get()]

def contains_special_chars(value):
    # Regex matches anything NOT letters, numbers, spaces, hyphens, underscores, or periods
    return bool(re.search(r"[^A-Za-z0-9 ._-]", value))

# --- Helper to safely handle rate-limited GET requests ---
def safe_api_get(url, headers, base_delay=0.3):
    """
    Performs a GET request with rate-limit handling (429).
    Automatically retries after the server's recommended wait time.
    """
    while True:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            time.sleep(base_delay)  # throttle between all calls
            return response

        if response.status_code == 429:
            try:
                msg = response.json().get("message", "")
                retry_after = int(msg.split("[")[1].split("]")[0])
            except:
                retry_after = 3  # fallback
            print(f"⚠️ Rate limited 429 — retrying in {retry_after} seconds")
            time.sleep(retry_after)
            continue

        return response

def generate_user_list():
    def task():
        try:
            # --- Disable UI while running ---
            for widget in root.winfo_children():
                if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                    widget.configure(state="disabled")

            # --- Get credentials ---
            client_id = client_id_entry.get().strip()
            client_secret = client_secret_entry.get().strip()
            status = user_state_var.get()

            if not client_id or not client_secret:
                messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
                for widget in root.winfo_children():
                    if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                        widget.configure(state="normal")
                return

            # --- Loading popup ---
            def bulk_add_queue():
                popup = tk.Toplevel(root)
                popup.title("Loading")
                popup.geometry("340x160")
                popup.resizable(False, False)
                popup.attributes("-topmost", True)
                popup.grab_set()

                tk.Label(popup, text="Fetching user data...", font=("Arial", 11)).pack(pady=10)
                progress = ttk.Progressbar(popup, mode="determinate", maximum=100)
                progress.pack(pady=5, padx=20, fill="x")
                counter_label = tk.Label(popup, text="0 users processed", font=("Arial", 9), fg="gray")
                counter_label.pack(pady=5)
                tk.Label(popup, text="Please wait, this may take a few minutes.", font=("Arial", 9), fg="gray").pack(pady=5)
                return popup, progress, counter_label

            popup, progress, counter_label = bulk_add_queue()

            # --- Setup Treeview ---
            selected_columns = get_selected_columns()
            setup_treeview(user_body_frame, selected_columns)

            # --- Authenticate ---
            api_base_url = "https://login.mypurecloud.jp"
            auth_url = f"{api_base_url}/oauth/token"
            auth_payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret
            }

            response = requests.post(auth_url, data=auth_payload)
            if response.status_code != 200:
                messagebox.showerror("Error", f"Failed to authenticate: {response.status_code}\n{response.text}")
                popup.destroy()
                return

            access_token = response.json().get("access_token")
            api_base_url_users = "https://api.mypurecloud.jp"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            # --- Fetch all users ---
            state_param = "any"
            users_url = f"{api_base_url_users}/api/v2/users?state={state_param}&expand=dateLastLogin,lastTokenIssued"
            all_users = []

            while users_url:
                response = safe_api_get(users_url, headers)
                if response.status_code == 200:
                    data = response.json()
                    all_users.extend(data.get("entities", []))
                    users_url = data.get("nextUri")
                    if users_url:
                        users_url = f"{api_base_url_users}{users_url}"
                else:
                    messagebox.showerror("Error", f"Failed to retrieve users: {response.status_code}\n{response.text}")
                    popup.destroy()
                    return

            # --- Filter by state ---
            if status in ["Active", "Inactive", "Deleted"]:
                filtered_users = [u for u in all_users if u.get("state") == status.lower()]
            else:
                filtered_users = all_users

            total_users = len(filtered_users)
            if total_users == 0:
                popup.destroy()
                messagebox.showinfo("No Results", "No users found matching the criteria.")
                return

            # --- Process each user ---
            for i, user in enumerate(filtered_users, start=1):
                popup.title(f"Processing user {i} of {total_users}")
                progress["value"] = (i / total_users) * 100
                counter_label.config(text=f"Processed {i}/{total_users} users")
                popup.update_idletasks()

                user_id = user.get("id")

                # --- Department ---
                user_details_url = f"{api_base_url_users}/api/v2/users/{user_id}"
                user_details_response = safe_api_get(user_details_url, headers)

                if user_details_response.status_code == 200:
                    user_details = user_details_response.json()
                    department = user_details.get("department", "N/A")
                    if isinstance(department, str) and contains_special_chars(department):
                        print(f"Special characters detected in department: {department}")
                    user["department"] = department
                else:
                    print(f"Failed to retrieve department for user {user_id}")
                    print("Status:", user_details_response.status_code)
                    print("Response:", user_details_response.text)
                    user["department"] = "Error retrieving department"

                # --- Licenses ---
                license_url = f"{api_base_url_users}/api/v2/license/users/{user_id}"
                license_response = safe_api_get(license_url, headers)
                user["licenseList"] = [lic.get("description", lic.get("id")) for lic in license_response.json().get("licenses", [])] if license_response.status_code == 200 else ["Error retrieving licenses"]

                # --- Roles ---
                roles_url = f"{api_base_url_users}/api/v2/users/{user_id}/roles"
                roles_response = safe_api_get(roles_url, headers)
                user["roleList"] = [role.get("name", role.get("id")) for role in roles_response.json().get("roles", [])] if roles_response.status_code == 200 else ["Error retrieving roles"]

                # --- Queues ---
                queues_url = f"{api_base_url_users}/api/v2/users/{user_id}/queues"
                queues_response = safe_api_get(queues_url, headers)
                user["queueList"] = [queue.get("name", queue.get("id")) for queue in queues_response.json().get("entities", [])] if queues_response.status_code == 200 else ["Error retrieving queues"]

                # --- Convert LastLogin to UTC+8 ---
                last_login_utc = user.get("dateLastLogin")
                if last_login_utc:
                    try:
                        utc_dt = datetime.fromisoformat(last_login_utc.replace("Z", "+00:00"))
                        utc8_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
                        user["dateLastLogin"] = utc8_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        user["dateLastLogin"] = last_login_utc

            # --- Update Treeview & Export CSV ---
            def update_treeview():
                user_tree.delete(*user_tree.get_children())
                csv_data = []

                for user in filtered_users:
                    user_data = {
                        "ID": user.get('id', 'N/A'),
                        "Name": user.get('name', 'N/A'),
                        "Email": user.get('email', 'N/A'),
                        "State": user.get('state', 'N/A'),
                        "Department": user.get("department", "N/A"),
                        "Licenses": ", ".join(user.get("licenseList", ["N/A"])),
                        "Roles": ", ".join(user.get("roleList", ["N/A"])),
                        "Division": user.get("division", {}).get("name", "N/A"),
                        "ACDAutoAnswer": user.get("acdAutoAnswer", "N/A"),
                        "LastLogin": user.get("dateLastLogin", "N/A"),
                        "Queues": ", ".join(user.get("queueList", ["N/A"]))
                    }

                    row_values = [user_data.get(col, "N/A") for col in selected_columns]
                    user_tree.insert("", tk.END, values=row_values)
                    csv_data.append(user_data)

                popup.destroy()

                file_path = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    filetypes=[("CSV files", "*.csv")],
                    title="Save As",
                    initialfile="genesys_users.csv"
                )

                if file_path:
                    with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=selected_columns)
                        writer.writeheader()
                        for row in csv_data:
                            writer.writerow({col: row.get(col, "N/A") for col in selected_columns})
                    messagebox.showinfo("Completed", f"User list generation completed.\nData exported to:\n{file_path}")
                else:
                    messagebox.showinfo("Cancelled", "Export cancelled by user.")

                for widget in root.winfo_children():
                    if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                        widget.configure(state="normal")

            user_tree.after(0, update_treeview)
            user_footer_frame.pack(fill="x", padx=5, pady=(0, 5))

        except Exception as e:
            messagebox.showerror("Error", str(e))
            try:
                popup.destroy()
            except:
                pass
            for widget in root.winfo_children():
                if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                    widget.configure(state="normal")

    threading.Thread(target=task, daemon=True).start()

def generate_user_list_in_queue():
    client_id = client_id_entry.get().strip()
    client_secret = client_secret_entry.get().strip()

    if not client_id or not client_secret:
        messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
        return

    api_base_url = "https://login.mypurecloud.jp"
    auth_url = f"{api_base_url}/oauth/token"
    auth_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    response = requests.post(auth_url, data=auth_payload)
    if response.status_code != 200:
        messagebox.showerror("Error", f"Failed to authenticate: {response.status_code}\n{response.text}")
        return

    access_token = response.json().get("access_token")
    api_base_url_users = "https://api.mypurecloud.jp"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # members_url = f"{api_base_url_users}/api/v2/routing/queues/{queue_id}/members?pageSize=100"

def export_queues():
    # --- Authenticate to Genesys Cloud ---
    client_id = client_id_entry.get().strip()
    client_secret = client_secret_entry.get().strip()

    if not client_id or not client_secret:
        messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
        return

    auth_url = "https://login.mypurecloud.jp/oauth/token"
    auth_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    auth_response = requests.post(auth_url, data=auth_payload)
    if auth_response.status_code != 200:
        messagebox.showerror(
            "Authentication Failed",
            f"{auth_response.status_code}: {auth_response.text}"
        )
        return

    access_token = auth_response.json().get("access_token")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    api_base_url = "https://api.mypurecloud.jp/api/v2"

    # --- Manila Time (consistent with your scripts) ---
    MANILA = timezone(timedelta(hours=8))
    today_manila = (datetime.now(timezone.utc) + timedelta(hours=8)).date()

    # --- Retrieve ALL queues ---
    all_queues = []
    next_page = f"{api_base_url}/routing/queues?pageSize=100"

    while next_page:
        queue_response = requests.get(next_page, headers=headers)
        if queue_response.status_code != 200:
            messagebox.showerror(
                "API Error",
                f"Failed to retrieve queues: {queue_response.status_code}"
            )
            return

        data = queue_response.json()
        all_queues.extend(data.get("entities", []))

        next_page = data.get("nextUri")
        if next_page:
            next_page = f"https://api.mypurecloud.jp{next_page}"

        time.sleep(0.2)  # avoid rate limits

    # --- Export to CSV ---
    output_file = f"queues_{today_manila}.csv"

    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["id", "name", "division"])

        for queue in all_queues:
            writer.writerow([
                queue.get("id", ""),
                queue.get("name", ""),
                queue.get("division", {}).get("name", "")
            ])

    messagebox.showinfo(
        "Export Complete",
        f"Successfully exported {len(all_queues)} queues.\n\nFile: {output_file}"
    )

def bulk_add_queue():
    popup = tk.Toplevel(root)
    popup.title("Bulk: Add Queues")
    popup.geometry("360x180")
    popup.resizable(False, False)
    popup.attributes("-topmost", True)
    popup.grab_set()  # Prevent focus loss

    # --- Frame container ---
    popup_parent_frame = tk.LabelFrame(popup, bg="#eaeaf2", text="", padx=10, pady=10)
    popup_parent_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # --- Header ---
    popup_header_lbl = tk.Label(
        popup_parent_frame,
        text="Choose an action below:",
        font=("Segoe UI", 10, "bold italic"),
        bg="#eaeaf2"
    )
    popup_header_lbl.pack(pady=5)

    # --- Import CSV File ---
    def import_csv_file():
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv")]
        )

        if not file_path:
            messagebox.showinfo("Cancelled", "No file selected.")
            return
        popup.destroy()

        queue_data = []

        # Read queue data from CSV file
        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    wrap_up_name = row.get("queueName", "").strip()
                    division = row.get("division", "").strip()
                    if wrap_up_name:
                        queue_data.append({"name": wrap_up_name, "division": division})
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import or process file:\n{str(e)}")
            return

        messagebox.showinfo("File Imported", f"Imported {len(queue_data)} queues from:\n{file_path}")

        # --- Authenticate to Genesys Cloud ---
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()

        if not client_id or not client_secret:
            messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
            return
        popup.destroy()

        auth_url = "https://login.mypurecloud.jp/oauth/token"
        auth_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }

        auth_response = requests.post(auth_url, data=auth_payload)
        if auth_response.status_code != 200:
            messagebox.showerror("Authentication Failed", f"{auth_response.status_code}: {auth_response.text}")
            return

        access_token = auth_response.json().get("access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        api_base_url = "https://api.mypurecloud.jp/api/v2"
        create_queue_url = f"{api_base_url}/routing/queues"

        success_count = 0
        exist_count = 0
        fail_count = 0

        # --- Step 1: Process CSV queues ---
        for q in queue_data:
            wrap_up_name = q["name"]
            division_name = q["division"]

            # --- Get division ID if provided ---
            division_id = None
            if division_name:
                div_response = requests.get(f"{api_base_url}/authorization/divisions", headers=headers)
                if div_response.status_code == 200:
                    div_results = div_response.json().get("entities", [])
                    for d in div_results:
                        if d.get("name", "").lower() == division_name.lower():
                            division_id = d.get("id")
                            break

            # --- Check if queue already exists ---
            check_url = f"{api_base_url}/routing/queues?name={wrap_up_name}"
            check_response = requests.get(check_url, headers=headers)
            time.sleep(0.2)

            if check_response.status_code == 200:
                results = check_response.json().get("entities", [])
                if any(qr.get("name", "").lower() == wrap_up_name.lower() for qr in results):
                    print(f"⚠️ Queue already exists: {wrap_up_name}")
                    exist_count += 1
                    continue

            # --- Build request body ---
            body = {"name": wrap_up_name}
            if division_id:
                body["division"] = {"id": division_id}

            # --- Create queue ---
            response = requests.post(create_queue_url, headers=headers, json=body)
            time.sleep(0.3)

            if response.status_code in (200, 201):
                success_count += 1
                print(f"✅ Queue created: {wrap_up_name}")
            elif response.status_code == 409:
                exist_count += 1
                print(f"⚠️ Queue already exists (409): {wrap_up_name}")
                popup.destroy()
            else:
                fail_count += 1
                print(f"❌ Failed to create queue: {wrap_up_name} - {response.status_code}: {response.text}")
                popup.destroy()

        # --- Summary ---
        messagebox.showinfo(
            "Bulk Add Complete",
            f"Queues processed: {len(queue_data)}\n"
            f"✅ Created: {success_count}\n"
            f"⚠️ Already Exists: {exist_count}\n"
            f"❌ Failed: {fail_count}"
        )
        popup.destroy()

        # --- Step 2: Retrieve all queues from Genesys (and filter by today Manila date) ---
        all_queues = []
        next_page = f"{api_base_url}/routing/queues?pageSize=100"

        from datetime import datetime, timezone, timedelta

        MANILA = timezone(timedelta(hours=8))
        # today's date in Asia/Manila
        today_manila = (datetime.now(timezone.utc) + timedelta(hours=8)).date()

        while next_page:
            queue_response = requests.get(next_page, headers=headers)
            if queue_response.status_code != 200:
                print(f"❌ Failed to retrieve queues: {queue_response.status_code}")
                break

            data = queue_response.json()
            all_queues.extend(data.get("entities", []))
            next_page = data.get("nextUri")
            if next_page:
                next_page = f"https://api.mypurecloud.jp{next_page}"
            time.sleep(0.2)

        # --- Filter queues created today (Manila) ---
        queues_created_today = []
        for q in all_queues:
            date_str = q.get("dateCreated")
            if not date_str:
                continue
            try:
                # parse ISO timestamp (handle 'Z')
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                # convert to Manila timezone
                dt_manila = dt.astimezone(MANILA)
                if dt_manila.date() == today_manila:
                    queues_created_today.append(q)
            except Exception as ex:
                # if parsing fails, skip
                print(f"⚠️ Failed to parse dateCreated '{date_str}': {ex}")
                continue

        # --- Fetch createdBy user names (cache to avoid repeated API calls) ---
        user_cache = {}

        for q in queues_created_today:
            created_by = q.get("createdBy")
            created_by_id = None
            created_by_name = ""

            # Handle both object and string formats
            if isinstance(created_by, dict):
                created_by_id = created_by.get("id")
                created_by_name = created_by.get("name", "")
            elif isinstance(created_by, str):
                created_by_id = created_by

            # If we still don't have a name, fetch it via API
            if created_by_id and not created_by_name:
                if created_by_id in user_cache:
                    created_by_name = user_cache[created_by_id]
                else:
                    try:
                        user_resp = requests.get(f"{api_base_url}/users/{created_by_id}", headers=headers)
                        time.sleep(0.15)
                        if user_resp.status_code == 200:
                            created_by_name = user_resp.json().get("name", "")
                        else:
                            created_by_name = created_by_id  # fallback
                    except Exception:
                        created_by_name = created_by_id
                    user_cache[created_by_id] = created_by_name

            q["_created_by_name"] = created_by_name or "(unknown)"


        # --- Step 3: Update Treeview with queues created today ---
        try:
            if "queues_table" in globals():
                # clear existing rows
                for item in queues_table.get_children():
                    queues_table.delete(item)

                # insert only queues created today
                for q in queues_created_today:
                    # date string formatted for display in Manila timezone
                    date_str = q.get("dateCreated", "")
                    display_date = ""
                    try:
                        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        display_date = dt.astimezone(MANILA).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        display_date = date_str

                    # get member count
                    member_count = q.get("memberCount", 0)

                    # insert into tree table
                    queues_table.insert("", "end", values=(
                        q.get("id", ""),
                        q.get("name", ""),
                        q.get("division", {}).get("name", ""),
                        display_date,
                        q.get("_created_by_name", ""),
                        member_count
                    ))

                messagebox.showinfo(
                    "Treeview Updated",
                    f"{len(queues_created_today)} queues created today were loaded into the table."
                )
        except Exception as e:
            print(f"⚠️ Failed to insert into Treeview: {e}")
        popup.destroy()

    # --- Export CSV Template ---
    def export_csv_template():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save CSV Template As",
            initialfile="Bulk_Add_Queues.csv"
        )

        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["queueName", "division"])
                messagebox.showinfo("Template Exported", f"Template saved:\n{file_path}")
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export template:\n{e}")
        else:
            messagebox.showinfo("Cancelled", "Export cancelled by user.")
            popup.destroy()

    # --- Buttons ---
    import_btn = tk.Button(
        popup_parent_frame,
        text="📂 Import CSV File",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#273F4F",
        fg="white",
        command=import_csv_file
    )
    import_btn.pack(pady=5)

    export_btn = tk.Button(
        popup_parent_frame,
        text="💾 Export CSV Template",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#DC5F00",
        fg="white",
        command=export_csv_template
    )
    export_btn.pack(pady=5)
    return popup

def bulk_assign_queue():
    popup = tk.Toplevel(root)
    popup.title("Bulk: Assign User to Queues")
    popup.geometry("360x180")
    popup.resizable(False, False)
    popup.attributes("-topmost", True)
    popup.grab_set()  # Prevent focus loss

    # --- Frame container ---
    popup_parent_frame = tk.LabelFrame(popup, bg="#eaeaf2", text="", padx=10, pady=10)
    popup_parent_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # --- Header ---
    popup_header_lbl = tk.Label(
        popup_parent_frame,
        text="Choose an action below:",
        font=("Segoe UI", 10, "bold italic"),
        bg="#eaeaf2"
    )
    popup_header_lbl.pack(pady=5)

    def import_csv_file():
        # --- Select CSV File ---
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv")]
        )

        if not file_path:
            messagebox.showinfo("Cancelled", "No file selected.")
            popup.destroy()
            return

        assignments = []

        # --- Read userId and queueId data ---
        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                required_columns = {"userId", "queueId"}
                if not required_columns.issubset(reader.fieldnames):
                    messagebox.showerror(
                        "Invalid CSV Format",
                        "CSV must contain 'userId' and 'queueId' columns."
                    )
                    return

                for row in reader:
                    user_id = row.get("userId", "").strip()
                    queue_id = row.get("queueId", "").strip()
                    if user_id and queue_id:
                        assignments.append({"userId": user_id, "queueId": queue_id})

            if not assignments:
                messagebox.showwarning("No Data", "No valid userId and queueId pairs found.")
                popup.destroy()
                return

        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")
            popup.destroy()
            return

        # --- Ask for confirmation ---
        if not messagebox.askyesno("Confirm", f"Proceed to assign {len(assignments)} users to queues?"):
            return

        # --- Authenticate to Genesys Cloud ---
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()

        if not client_id or not client_secret:
            messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
            return

        auth_url = "https://login.mypurecloud.jp/oauth/token"
        auth_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }

        auth_response = requests.post(auth_url, data=auth_payload)
        if auth_response.status_code != 200:
            messagebox.showerror("Authentication Failed", f"{auth_response.status_code}: {auth_response.text}")
            popup.destroy()
            return

        access_token = auth_response.json().get("access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        api_base_url = "https://api.mypurecloud.jp/api/v2"

        # --- Create popup for progress ---
        progress_popup = tk.Toplevel(root)
        progress_popup.title("Assigning Users to Queues")
        progress_popup.geometry("380x160")
        progress_popup.resizable(False, False)
        progress_popup.attributes("-topmost", True)
        progress_popup.grab_set()

        tk.Label(progress_popup, text="Processing assignments...", font=("Arial", 11)).pack(pady=10)
        progress = ttk.Progressbar(progress_popup, mode="determinate", maximum=len(assignments))
        progress.pack(pady=5, padx=20, fill="x")
        counter_label = tk.Label(progress_popup, text="0 / 0 completed", font=("Arial", 9), fg="gray")
        counter_label.pack(pady=5)
        progress_popup.update_idletasks()

        def run_assignment():
            success_count = 0
            error_count = 0

            # Group assignments by queueId
            queue_map = {}
            for item in assignments:
                queue_map.setdefault(item["queueId"], []).append(item["userId"])

            # Process each queue
            for queue_id, user_ids in queue_map.items():
                # Genesys endpoint supports up to 100 users per request
                for i in range(0, len(user_ids), 100):
                    batch = user_ids[i:i + 100]
                    url = f"{api_base_url}/routing/queues/{queue_id}/members"
                    payload = [{"id": uid, "type": "USER"} for uid in batch]

                    try:
                        response = requests.post(url, headers=headers, json=payload)
                        if response.status_code in [200, 201, 204]:
                            success_count += len(batch)
                        else:
                            error_count += len(batch)
                            print(f"❌ Failed: {response.status_code} - {response.text}")
                    except Exception as e:
                        print(f"Error assigning batch to queue {queue_id}: {e}")
                        error_count += len(batch)

                    progress["value"] += len(batch)
                    counter_label.config(text=f"{success_count + error_count}/{len(assignments)} completed")
                    progress_popup.update_idletasks()

            progress_popup.destroy()
            messagebox.showinfo(
                "Process Completed",
                f"✅ Successfully assigned: {success_count}\n❌ Failed: {error_count}\n\nFile: {file_path}"
            )
            popup.destroy()

        threading.Thread(target=run_assignment).start()

     # --- Export CSV Template ---
    def export_csv_template():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save CSV Template As",
            initialfile="Bulk_Assign_Users_to_Queue.csv"
        )

        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["queueId", "userId"])
                messagebox.showinfo("Template Exported", f"Template saved:\n{file_path}")
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export template:\n{e}")
        else:
            messagebox.showinfo("Cancelled", "Export cancelled by user.")
            popup.destroy()

    # --- Buttons ---
    import_btn = tk.Button(
        popup_parent_frame,
        text="📂 Import CSV File",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#273F4F",
        fg="white",
        command=import_csv_file
    )
    import_btn.pack(pady=5)

    export_btn = tk.Button(
        popup_parent_frame,
        text="💾 Export CSV Template",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#DC5F00",
        fg="white",
        command=export_csv_template
    )
    export_btn.pack(pady=5)
    return popup

def bulk_assign_wrapup():
    popup = tk.Toplevel(root)
    popup.title("Bulk: Assign Wrapups to Queues")
    popup.geometry("360x180")
    popup.resizable(False, False)
    popup.attributes("-topmost", True)
    popup.grab_set()

    popup_parent_frame = tk.LabelFrame(popup, bg="#eaeaf2", padx=10, pady=10)
    popup_parent_frame.pack(fill="both", expand=True, padx=10, pady=10)

    tk.Label(
        popup_parent_frame,
        text="Choose an action below:",
        font=("Segoe UI", 10, "bold italic"),
        bg="#eaeaf2"
    ).pack(pady=5)

    # ------------------------
    # IMPORT CSV FILE
    # ------------------------
    def import_csv_file():
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv")]
        )
        if not file_path:
            messagebox.showinfo("Cancelled", "No file selected.")
            popup.destroy()
            return

        assignments = []

        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                required_columns = {"queueId", "wrapupCodeId"}
                if not required_columns.issubset(reader.fieldnames):
                    messagebox.showerror("Invalid CSV Format",
                        "CSV must contain 'queueId' and 'wrapupCodeId' columns.")
                    return
                for row in reader:
                    queue_id = row["queueId"].strip()
                    wrapup_id = row["wrapupCodeId"].strip()
                    if queue_id and wrapup_id:
                        assignments.append({"queueId": queue_id, "wrapupCodeId": wrapup_id})

            if not assignments:
                messagebox.showwarning("No Data", "No valid queueId / wrapupCodeId pairs found.")
                popup.destroy()
                return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")
            popup.destroy()
            return

        if not messagebox.askyesno(
            "Confirm",
            f"Proceed to assign {len(assignments)} wrapup codes to queues?"
        ):
            return

        # ------------------------
        # AUTHENTICATE
        # ------------------------
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()

        if not client_id or not client_secret:
            messagebox.showerror("Missing Credentials",
                                 "Client ID and Client Secret cannot be empty.")
            return

        auth_url = "https://login.mypurecloud.jp/oauth/token"
        auth_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }
        auth_response = requests.post(auth_url, data=auth_payload)
        if auth_response.status_code != 200:
            messagebox.showerror("Authentication Failed",
                                 f"{auth_response.status_code}: {auth_response.text}")
            popup.destroy()
            return

        access_token = auth_response.json().get("access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        api_base = "https://api.mypurecloud.jp/api/v2"

        # ------------------------
        # PROGRESS POPUP
        # ------------------------
        progress_popup = tk.Toplevel(root)
        progress_popup.title("Assigning Wrapup Codes")
        progress_popup.geometry("380x160")
        progress_popup.resizable(False, False)
        progress_popup.attributes("-topmost", True)
        progress_popup.grab_set()

        tk.Label(progress_popup, text="Processing...", font=("Arial", 11)).pack(pady=10)
        progress = ttk.Progressbar(progress_popup, mode="determinate", maximum=len(assignments))
        progress.pack(pady=5, padx=20, fill="x")
        counter_label = tk.Label(progress_popup, text="0 / 0 completed", font=("Arial", 9), fg="gray")
        counter_label.pack(pady=5)

        # ------------------------
        # RUN ASSIGNMENT
        # ------------------------
        def run_assignment():
            success_count = 0
            error_count = 0
            invalid_wrapups = []

            # Group assignments by queue
            queue_map = {}
            for item in assignments:
                queue_map.setdefault(item["queueId"], []).append(item["wrapupCodeId"])

            # Process each queue
            for queue_id, wrapup_ids in queue_map.items():
                # Validate wrapup IDs individually
                valid_wrapup_ids = []
                for wid in wrapup_ids:
                    try:
                        resp = requests.get(
                            f"{api_base}/routing/wrapupcodes",
                            headers=headers,
                            params={"id": wid.strip()}
                        )
                        resp.raise_for_status()
                        entities = resp.json().get("entities", [])
                        if entities:
                            valid_wrapup_ids.append({"id": wid.strip()})
                        else:
                            invalid_wrapups.append({"queueId": queue_id, "wrapupCodeId": wid})
                    except Exception as e:
                        print(f"❌ Error validating wrapup {wid} for queue {queue_id}: {e}")
                        invalid_wrapups.append({"queueId": queue_id, "wrapupCodeId": wid})

                if not valid_wrapup_ids:
                    continue  # Skip queue if no valid wrapups

                # Bulk POST to assign wrapups
                try:
                    resp = requests.post(
                        f"{api_base}/routing/queues/{queue_id}/wrapupcodes",
                        headers=headers,
                        json=valid_wrapup_ids
                    )
                    if resp.status_code in (200, 201, 204):
                        success_count += len(valid_wrapup_ids)
                    else:
                        print(f"❌ Failed batch for queue {queue_id}: {resp.status_code} - {resp.text}")
                        error_count += len(valid_wrapup_ids)
                except Exception as e:
                    print(f"❌ Exception for queue {queue_id}: {e}")
                    error_count += len(valid_wrapup_ids)

                for _ in valid_wrapup_ids:
                    progress["value"] += 1
                    counter_label.config(text=f"{success_count + error_count}/{len(assignments)} completed")
                    progress_popup.update_idletasks()

            progress_popup.destroy()

            # Show results
            msg = f"✅ Successfully assigned: {success_count}\n❌ Failed: {error_count}"
            if invalid_wrapups:
                msg += "\n\n⚠ Invalid wrapup IDs skipped:\n" + \
                       "\n".join([f"{i['wrapupCodeId']} (queue {i['queueId']})" for i in invalid_wrapups])

            messagebox.showinfo("Process Completed", msg)
            popup.destroy()

        threading.Thread(target=run_assignment).start()

    # ------------------------
    # EXPORT TEMPLATE
    # ------------------------
    def export_csv_template():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save CSV Template As",
            initialfile="Bulk_Assign_Wrapup_to_Queue.csv"
        )
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["queueId", "wrapupCodeId"])
                messagebox.showinfo("Template Exported", f"Template saved:\n{file_path}")
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export template:\n{e}")
        else:
            messagebox.showinfo("Cancelled", "Export cancelled by user.")
            popup.destroy()

    # ------------------------
    # BUTTONS
    # ------------------------
    tk.Button(
        popup_parent_frame,
        text="📂 Import CSV File",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#273F4F",
        fg="white",
        command=import_csv_file
    ).pack(pady=5)

    tk.Button(
        popup_parent_frame,
        text="💾 Export CSV Template",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#DC5F00",
        fg="white",
        command=export_csv_template
    ).pack(pady=5)

    return popup

def refresh_queue_table():

# --- Authenticate to Genesys Cloud ---
    client_id = client_id_entry.get().strip()
    client_secret = client_secret_entry.get().strip()

    if not client_id or not client_secret:
        messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
        return

    auth_url = "https://login.mypurecloud.jp/oauth/token"
    auth_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    auth_response = requests.post(auth_url, data=auth_payload)
    if auth_response.status_code != 200:
        messagebox.showerror("Authentication Failed", f"{auth_response.status_code}: {auth_response.text}")
        return

    access_token = auth_response.json().get("access_token")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    api_base_url = "https://api.mypurecloud.jp/api/v2"

    all_queues = []
    next_page = f"{api_base_url}/routing/queues?pageSize=100"

    from datetime import datetime, timezone, timedelta

    MANILA = timezone(timedelta(hours=8))
    # today's date in Asia/Manila
    today_manila = (datetime.now(timezone.utc) + timedelta(hours=8)).date()

    while next_page:
        queue_response = requests.get(next_page, headers=headers)
        if queue_response.status_code != 200:
            print(f"❌ Failed to retrieve queues: {queue_response.status_code}")
            break

        data = queue_response.json()
        all_queues.extend(data.get("entities", []))
        next_page = data.get("nextUri")
        if next_page:
            next_page = f"https://api.mypurecloud.jp{next_page}"
        time.sleep(0.2)

    # --- Filter queues created today (Manila) ---
    queues_created_today = []
    for q in all_queues:
        date_str = q.get("dateCreated")
        if not date_str:
            continue
        try:
            # parse ISO timestamp (handle 'Z')
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            # convert to Manila timezone
            dt_manila = dt.astimezone(MANILA)
            if dt_manila.date() == today_manila:
                queues_created_today.append(q)
        except Exception as ex:
            # if parsing fails, skip
            print(f"⚠️ Failed to parse dateCreated '{date_str}': {ex}")
            continue

    # --- Fetch createdBy user names (cache to avoid repeated API calls) ---
    user_cache = {}

    for q in queues_created_today:
        created_by = q.get("createdBy")
        created_by_id = None
        created_by_name = ""

        # Handle both object and string formats
        if isinstance(created_by, dict):
            created_by_id = created_by.get("id")
            created_by_name = created_by.get("name", "")
        elif isinstance(created_by, str):
            created_by_id = created_by

        # If we still don't have a name, fetch it via API
        if created_by_id and not created_by_name:
            if created_by_id in user_cache:
                created_by_name = user_cache[created_by_id]
            else:
                try:
                    user_resp = requests.get(f"{api_base_url}/users/{created_by_id}", headers=headers)
                    time.sleep(0.15)
                    if user_resp.status_code == 200:
                        created_by_name = user_resp.json().get("name", "")
                    else:
                        created_by_name = created_by_id  # fallback
                except Exception:
                    created_by_name = created_by_id
                user_cache[created_by_id] = created_by_name

        q["_created_by_name"] = created_by_name or "(unknown)"


    # --- Step 3: Update Treeview with queues created today ---
    try:
        if "queues_table" in globals():
            # clear existing rows
            for item in queues_table.get_children():
                queues_table.delete(item)

            # insert only queues created today
            for q in queues_created_today:
                # date string formatted for display in Manila timezone
                date_str = q.get("dateCreated", "")
                display_date = ""
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    display_date = dt.astimezone(MANILA).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    display_date = date_str

                # get member count
                member_count = q.get("memberCount", 0)

                # insert into tree table
                queues_table.insert("", "end", values=(
                    q.get("id", ""),
                    q.get("name", ""),
                    q.get("division", {}).get("name", ""),
                    display_date,
                    q.get("_created_by_name", ""),
                    member_count
                ))

            messagebox.showinfo(
                "Treeview Updated",
                f"{len(queues_created_today)} queues created today were loaded into the table."
            )
    except Exception as e:
        print(f"⚠️ Failed to insert into Treeview: {e}")

def refresh_wrapup_table():
    # --- Authenticate to Genesys Cloud ---
    client_id = client_id_entry.get().strip()
    client_secret = client_secret_entry.get().strip()

    if not client_id or not client_secret:
        messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
        return

    auth_url = "https://login.mypurecloud.jp/oauth/token"
    auth_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    auth_response = requests.post(auth_url, data=auth_payload)
    if auth_response.status_code != 200:
        messagebox.showerror("Authentication Failed", f"{auth_response.status_code}: {auth_response.text}")
        return

    access_token = auth_response.json().get("access_token")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    api_base_url = "https://api.mypurecloud.jp/api/v2"

    all_wrapup = []
    next_page = f"{api_base_url}/routing/wrapupcodes?pageSize=100"

    from datetime import datetime, timezone, timedelta
    MANILA = timezone(timedelta(hours=8))

    today_manila = (datetime.now(timezone.utc) + timedelta(hours=8)).date()

    # Step 1: Retrieve ALL pages
    while next_page:
        wrapup_response = requests.get(next_page, headers=headers)
        if wrapup_response.status_code != 200:
            print(f"❌ Failed to retrieve wrapup codes: {wrapup_response.status_code}")
            break

        data = wrapup_response.json()
        all_wrapup.extend(data.get("entities", []))

        next_page = data.get("nextUri")
        if next_page:
            next_page = f"https://api.mypurecloud.jp{next_page}"

        time.sleep(0.2)

    # Step 2: Filter today's wrapups
    wrapup_created_today = []
    for q in all_wrapup:
        date_str = q.get("dateCreated")
        if not date_str:
            continue
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            dt_manila = dt.astimezone(MANILA)
            if dt_manila.date() == today_manila:
                wrapup_created_today.append(q)
        except:
            continue

    # Step 3: Resolve "createdBy" names
    user_cache = {}
    for q in wrapup_created_today:
        created_by = q.get("createdBy")
        created_by_id = None
        created_by_name = ""

        if isinstance(created_by, dict):
            created_by_id = created_by.get("id")
            created_by_name = created_by.get("name", "")
        elif isinstance(created_by, str):
            created_by_id = created_by

        if created_by_id and not created_by_name:
            if created_by_id in user_cache:
                created_by_name = user_cache[created_by_id]
            else:
                user_resp = requests.get(f"{api_base_url}/users/{created_by_id}", headers=headers)
                time.sleep(0.15)
                if user_resp.status_code == 200:
                    created_by_name = user_resp.json().get("name", "")
                else:
                    created_by_name = created_by_id
                user_cache[created_by_id] = created_by_name

        q["_created_by_name"] = created_by_name or "(unknown)"

    # Step 4: Update Treeview
    if "wrapup_codes_table" in globals():
        for item in wrapup_codes_table.get_children():
            wrapup_codes_table.delete(item)

        for q in wrapup_created_today:
            date_str = q.get("dateCreated", "")
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                display_date = dt.astimezone(MANILA).strftime("%Y-%m-%d %H:%M:%S")
            except:
                display_date = date_str

            wrapup_codes_table.insert("", "end", values=(
                q.get("id", ""),
                q.get("name", ""),
                q.get("division", {}).get("name", ""),
                display_date,
                q.get("_created_by_name", "")
            ))

    # FINAL popup (only once)
    messagebox.showinfo(
        "Treeview Updated",
        f"{len(wrapup_created_today)} wrapup codes created today were loaded into the table."
    )

def export_wrapup_codes():
    # --- Authenticate to Genesys Cloud ---
    client_id = client_id_entry.get().strip()
    client_secret = client_secret_entry.get().strip()

    if not client_id or not client_secret:
        messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
        return

    auth_url = "https://login.mypurecloud.jp/oauth/token"
    auth_payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    auth_response = requests.post(auth_url, data=auth_payload)
    if auth_response.status_code != 200:
        messagebox.showerror(
            "Authentication Failed",
            f"{auth_response.status_code}: {auth_response.text}"
        )
        return

    access_token = auth_response.json().get("access_token")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    api_base_url = "https://api.mypurecloud.jp/api/v2"

    # --- Manila Time (kept for consistency with your scripts) ---
    MANILA = timezone(timedelta(hours=8))
    today_manila = (datetime.now(timezone.utc) + timedelta(hours=8)).date()

    # --- Retrieve ALL wrap-up codes ---
    all_wrapup = []
    next_page = f"{api_base_url}/routing/wrapupcodes?pageSize=100"

    while next_page:
        wrapup_response = requests.get(next_page, headers=headers)
        if wrapup_response.status_code != 200:
            messagebox.showerror(
                "API Error",
                f"Failed to retrieve wrap-up codes: {wrapup_response.status_code}"
            )
            return

        data = wrapup_response.json()
        all_wrapup.extend(data.get("entities", []))

        next_page = data.get("nextUri")
        if next_page:
            next_page = f"https://api.mypurecloud.jp{next_page}"

        time.sleep(0.2)  # avoid rate limits

    # --- Export to CSV ---
    output_file = f"wrapup_codes_{today_manila}.csv"

    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["id", "name", "division"])

        for code in all_wrapup:
            writer.writerow([
                code.get("id", ""),
                code.get("name", ""),
                code.get("division", {}).get("name", "")
            ])

    messagebox.showinfo(
        "Export Complete",
        f"Successfully exported {len(all_wrapup)} wrap-up codes.\n\nFile: {output_file}"
    )

def bulk_add_wrap_up():
    popup = tk.Toplevel(root)
    popup.title("Bulk: Add Wrap Up Codes")
    popup.geometry("360x180")
    popup.resizable(False, False)
    popup.attributes("-topmost", True)
    popup.grab_set()  # Prevent focus loss

    # --- Frame container ---
    popup_parent_frame = tk.LabelFrame(popup, bg="#eaeaf2", text="", padx=10, pady=10)
    popup_parent_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # --- Header ---
    popup_header_lbl = tk.Label(
        popup_parent_frame,
        text="Choose an action below:",
        font=("Segoe UI", 10, "bold italic"),
        bg="#eaeaf2"
    )
    popup_header_lbl.pack(pady=5)

    # --- Import CSV File ---
    def import_csv_file():
        file_path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv")]
        )
        if not file_path:
            messagebox.showinfo("Cancelled", "No file selected.")
            return
        popup.destroy()
        wrap_up_data = []
        # Read queue data from CSV file
        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    wrap_up_name = row.get("wrapUpName", "").strip()
                    division = row.get("division", "").strip()
                    if wrap_up_name:
                        wrap_up_data.append({"name": wrap_up_name, "division": division})
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import or process file:\n{str(e)}")
            return
        messagebox.showinfo("File Imported", f"Imported {len(wrap_up_data)} queues from:\n{file_path}")

         # --- Authenticate to Genesys Cloud ---
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()
        if not client_id or not client_secret:
            messagebox.showerror("Missing Credentials", "Client ID and Client Secret cannot be empty.")
            return
        popup.destroy()
        auth_url = "https://login.mypurecloud.jp/oauth/token"
        auth_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }
        auth_response = requests.post(auth_url, data=auth_payload)
        if auth_response.status_code != 200:
            messagebox.showerror("Authentication Failed", f"{auth_response.status_code}: {auth_response.text}")
            return
        access_token = auth_response.json().get("access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        api_base_url = "https://api.mypurecloud.jp/api/v2"
        create_queue_url = f"{api_base_url}/routing/wrapupcodes"
        success_count = 0
        exist_count = 0
        fail_count = 0

        # --- Step 1: Process CSV wrapup ---
        for w in wrap_up_data:
            wrap_up_name = w["name"]
            division_name = w["division"]

            # --- Get division ID if provided ---
            division_id = None
            if division_name:
                div_response = requests.get(f"{api_base_url}/authorization/divisions", headers=headers)
                if div_response.status_code == 200:
                    div_results = div_response.json().get("entities", [])
                    for d in div_results:
                        if d.get("name", "").lower() == division_name.lower():
                            division_id = d.get("id")
                            break
                
            # --- Check if wrap up already exist ---
            check_url = f"{api_base_url}/routing/wrapupcodes?name={wrap_up_name}"
            check_response = requests.get(check_url, headers=headers)
            time.sleep(0.2)

            if check_response.status_code == 200:
                results = check_response.json().get("entities", [])
                if any(qr.get("name", "").lower() == division_name.lower() for qr in results):
                    print(f"⚠️ Queue already exists: {division_name}")
                    exist_count += 1
                    continue

            # --- Build request body ---
            body = {"name": wrap_up_name}
            if division_id:
                body["division"] = {"id": division_id}

            # --- Create queue ---
            response = requests.post(create_queue_url, headers=headers, json=body)
            time.sleep(0.3)
            if response.status_code in (200, 201):
                success_count += 1
                print(f"✅ Wrapup created: {wrap_up_name}")
            elif response.status_code == 409:
                exist_count += 1
                print(f"⚠️ Wrapup already exists (409): {wrap_up_name}")
                popup.destroy()
            else:
                fail_count += 1
                print(f"❌ Failed to create wrapup: {wrap_up_name} - {response.status_code}: {response.text}")
                popup.destroy()

        # --- Summary ---
        messagebox.showinfo(
            "Bulk Add Complete",
            f"Wrapup codes processed: {len(wrap_up_name)}\n"
            f"✅ Created: {success_count}\n"
            f"⚠️ Already Exists: {exist_count}\n"
            f"❌ Failed: {fail_count}"
        )
        popup.destroy()

        # --- Step 2: Retrieve all wrapup from Genesys (and filter by today Manila date) ---
        all_wrapup = []
        next_page = f"{api_base_url}/routing/wrapupcodes?pageSize=100"
        from datetime import datetime, timezone, timedelta
        MANILA = timezone(timedelta(hours=8))
        # today's date in Asia/Manila
        today_manila = (datetime.now(timezone.utc) + timedelta(hours=8)).date()
        while next_page:
            wrapup_response = requests.get(next_page, headers=headers)
            if wrapup_response.status_code != 200:
                print(f"❌ Failed to retrieve queues: {wrapup_response.status_code}")
                break
            data = wrapup_response.json()
            all_wrapup.extend(data.get("entities", []))
            next_page = data.get("nextUri")
            if next_page:
                next_page = f"https://api.mypurecloud.jp{next_page}"
            time.sleep(0.2)

        # --- Filter wrapup created today (Manila) ---
        wrapup_created_today = []
        for q in all_wrapup:
            date_str = q.get("dateCreated")
            if not date_str:
                continue
            try:
                # parse ISO timestamp (handle 'Z')
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                # convert to Manila timezone
                dt_manila = dt.astimezone(MANILA)
                if dt_manila.date() == today_manila:
                    wrapup_created_today.append(q)
            except Exception as ex:
                # if parsing fails, skip
                print(f"⚠️ Failed to parse dateCreated '{date_str}': {ex}")
                continue
        # --- Fetch createdBy user names (cache to avoid repeated API calls) ---
        user_cache = {}
        for q in wrapup_created_today:
            created_by = q.get("createdBy")
            created_by_id = None
            created_by_name = ""
            # Handle both object and string formats
            if isinstance(created_by, dict):
                created_by_id = created_by.get("id")
                created_by_name = created_by.get("name", "")
            elif isinstance(created_by, str):
                created_by_id = created_by
            # If we still don't have a name, fetch it via API
            if created_by_id and not created_by_name:
                if created_by_id in user_cache:
                    created_by_name = user_cache[created_by_id]
                else:
                    try:
                        user_resp = requests.get(f"{api_base_url}/users/{created_by_id}", headers=headers)
                        time.sleep(0.15)
                        if user_resp.status_code == 200:
                            created_by_name = user_resp.json().get("name", "")
                        else:
                            created_by_name = created_by_id  # fallback
                    except Exception:
                        created_by_name = created_by_id
                    user_cache[created_by_id] = created_by_name
            q["_created_by_name"] = created_by_name or "(unknown)"
        
        # --- Step 3: Update Treeview with queues created today ---
        try:
            if "wrapup_codes_table" in globals():
                # clear existing rows
                for item in wrapup_codes_table.get_children():
                    wrapup_codes_table.delete(item)
                # insert only queues created today
                for q in wrapup_created_today:
                    # date string formatted for display in Manila timezone
                    date_str = q.get("dateCreated", "")
                    display_date = ""
                    try:
                        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        display_date = dt.astimezone(MANILA).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        display_date = date_str

                    # insert into tree table
                    wrapup_codes_table.insert("", "end", values=(
                        q.get("id", ""),
                        q.get("name", ""),
                        q.get("division", {}).get("name", ""),
                        display_date,
                        q.get("_created_by_name", "")
                    ))
                messagebox.showinfo(
                    "Treeview Updated",
                    f"{len(wrapup_created_today)} wrapup codes created today were loaded into the table."
                )
        except Exception as e:
            print(f"⚠️ Failed to insert into Treeview: {e}")
        popup.destroy()

    # --- Export CSV Template ---
    def export_csv_template():
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save CSV Template As",
            initialfile="Bulk_Add_Wrap_Up_Codes.csv"
        )
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["wrapupName", "division"])
                messagebox.showinfo("Template Exported", f"Template saved:\n{file_path}")
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export template:\n{e}")
        else:
            messagebox.showinfo("Cancelled", "Export cancelled by user.")
            popup.destroy()
            
    # --- Buttons ---
    import_btn = tk.Button(
        popup_parent_frame,
        text="📂 Import CSV File",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#273F4F",
        fg="white",
        command=import_csv_file
    )
    import_btn.pack(pady=5)
    export_btn = tk.Button(
        popup_parent_frame,
        text="💾 Export CSV Template",
        font=("Segoe UI", 9, "bold"),
        width=30,
        bg="#DC5F00",
        fg="white",
        command=export_csv_template
    )
    export_btn.pack(pady=5)
    return popup

def get_roles_and_permissions():
    def task():
        try:
            # --- Disable all buttons and entries while running ---
            for widget in root.winfo_children():
                if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                    widget.configure(state="disabled")

            # --- Get credentials ---
            client_id = client_id_entry.get().strip()
            client_secret = client_secret_entry.get().strip()
            user_id = user_id_entry.get().strip()

            if not client_id or not client_secret or not user_id:
                messagebox.showerror("Missing Fields", "Client ID, Client Secret, and User ID cannot be empty.")
                # Re-enable UI
                for widget in root.winfo_children():
                    if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                        widget.configure(state="normal")
                return

            # --- Show loading popup ---
            def bulk_add_queue():
                popup = tk.Toplevel(root)
                popup.title("Loading")
                popup.geometry("340x160")
                popup.resizable(False, False)
                popup.attributes("-topmost", True)
                popup.grab_set()  # Prevent focus loss

                tk.Label(popup, text="Retrieving roles and permissions...", font=("Arial", 11)).pack(pady=10)
                progress = ttk.Progressbar(popup, mode="determinate")
                progress.pack(pady=5, padx=20, fill="x")

                counter_label = tk.Label(popup, text="", font=("Arial", 9), fg="gray")
                counter_label.pack(pady=5)

                tk.Label(popup, text="Please wait, this may take a few minutes.", font=("Arial", 9), fg="gray").pack(pady=3)
                return popup, progress, counter_label

            popup, progress, counter_label = bulk_add_queue()

            # --- Clear previous table data ---
            for row in roles_and_permission_table.get_children():
                roles_and_permission_table.delete(row)

            # --- Authenticate ---
            auth_url = "https://login.mypurecloud.jp/oauth/token"
            auth_payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret
            }

            auth_response = requests.post(auth_url, data=auth_payload)
            if auth_response.status_code != 200:
                messagebox.showerror("Error", f"Authentication failed: {auth_response.status_code}\n{auth_response.text}")
                popup.destroy()
                return

            access_token = auth_response.json().get("access_token")
            if not access_token:
                messagebox.showerror("Error", "Failed to retrieve access token.")
                popup.destroy()
                return

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            # --- Get user name ---
            user_url = f"https://api.mypurecloud.jp/api/v2/users/{user_id}"
            user_response = requests.get(user_url, headers=headers)
            time.sleep(0.2)
            user_name = user_response.json().get("name", "N/A") if user_response.status_code == 200 else "N/A"

            # --- Get roles ---
            roles_url = f"https://api.mypurecloud.jp/api/v2/users/{user_id}/roles"
            roles_response = requests.get(roles_url, headers=headers)
            time.sleep(0.2)

            if roles_response.status_code != 200:
                messagebox.showerror("Error", f"Failed to retrieve user roles: {roles_response.status_code}\n{roles_response.text}")
                popup.destroy()
                return

            roles_data = roles_response.json().get("roles", [])
            if not roles_data:
                roles_and_permission_table.insert("", "end", values=("No roles found for user", "", "", "", "", ""))
                popup.destroy()
                return

            csv_rows = [["Role ID", "Role Name", "Role Description", "Domain", "Entity Name", "Actions"]]
            total_roles = len(roles_data)
            progress["maximum"] = total_roles

            # --- Process each role ---
            for i, role in enumerate(roles_data, start=1):
                popup.title(f"Processing role {i} of {total_roles}")
                counter_label.config(text=f"Processing role {i} of {total_roles}")
                progress["value"] = i
                popup.update_idletasks()

                role_id = role.get("id", "N/A")

                role_details_url = f"https://api.mypurecloud.jp/api/v2/authorization/roles/{role_id}"
                role_details_response = requests.get(role_details_url, headers=headers)
                time.sleep(0.2)

                if role_details_response.status_code != 200:
                    roles_and_permission_table.insert("", "end", values=(role_id, "Error retrieving role", "", "", "", ""))
                    csv_rows.append([role_id, "Error", "Error retrieving details", "", "", ""])
                    continue

                role_details_data = role_details_response.json()
                role_name = role_details_data.get("name", "N/A")
                role_description = role_details_data.get("description", "No description available")
                permission_policies = role_details_data.get("permissionPolicies", [])

                if not permission_policies:
                    roles_and_permission_table.insert("", "end", values=(role_id, role_name, role_description, "No permissions", "", ""))
                    csv_rows.append([role_id, role_name, role_description, "No permissions", "", ""])
                    continue

                for permission in permission_policies:
                    domain = permission.get("domain", "N/A")
                    entity_name = permission.get("entityName", "N/A")
                    actions = ", ".join(permission.get("actionSet", []))

                    roles_and_permission_table.insert("", "end", values=(role_id, role_name, role_description, domain, entity_name, actions))
                    csv_rows.append([role_id, role_name, role_description, domain, entity_name, actions])

            # --- Save results to CSV ---
            popup.destroy()
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Save As",
                initialfile=f"user_{user_name}_roles_with_permissions.csv"
            )

            if file_path:
                try:
                    with open(file_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerows(csv_rows)
                    messagebox.showinfo("Success", f"User roles and permissions exported successfully:\n{file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save CSV: {str(e)}")
            else:
                messagebox.showinfo("Cancelled", "Export cancelled by user.")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            try:
                popup.destroy()
            except:
                pass
        finally:
            # --- Re-enable all inputs and buttons ---
            for widget in root.winfo_children():
                if isinstance(widget, (tk.Button, ttk.Combobox, tk.Entry)):
                    widget.configure(state="normal")

    threading.Thread(target=task, daemon=True).start()

def on_selection(event):
    selected_value = user_state.get()

root = ThemedTk(theme="arc")
root.geometry("500x400+390+140")
root.title("Genesys Cloud Script")

def resource_path(relative_path):
    """Get absolute path to resource, works in dev and in PyInstaller exe."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

icon_path = resource_path("src/genesys_cloud_icon.png")
icon_img = Image.open(icon_path)
icon_tk = ImageTk.PhotoImage(icon_img)

root.iconphoto(False, icon_tk)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Menu Bar
menu_frame = tk.Frame(root, bg="#343d40", border=0)
menu_frame.pack(fill="x", side="top")

# Icons
genesys_logo = load_icon_from_web("https://img.icons8.com/?size=100&id=99sIkfseOpyU&format=png&color=f0f0f0", size=(25, 25))
home_icon = load_icon_from_web("https://img.icons8.com/?size=100&id=12229&format=png&color=000000", size=(15,15))
user_icon = load_icon_from_web("https://img.icons8.com/?size=100&id=13042&format=png&color=000000", size=(15, 15))
settings_icon = load_icon_from_web("https://img.icons8.com/?size=100&id=EHYRINeSAUFT&format=png&color=000000", size=(15, 15))

# Menu Bar Buttons
set_genesys_logo_icon = tk.Label(menu_frame, image=genesys_logo, bg="#DC5F00")
set_genesys_logo_icon.grid(column=0, row=1)

menu_btn_home = tk.Button(menu_frame, text=" Home ", border=0, bg="#273F4F", fg="white", image=home_icon, compound="left", font=("Segoe UI", 10, "bold"), command=show_home)
menu_btn_home.grid(column=1, row=1, sticky="nsew")

menu_btn_user_management = tk.Button(menu_frame, text=" User Management ", border=0, bg="#343d40", fg="white", image=user_icon, compound="left", font=("Segoe UI", 10), command=show_user_management)
menu_btn_user_management.grid(column=2, row=1, sticky="nsew")

menu_btn_settings = tk.Button(menu_frame, text=" Settings ", border=0, bg="#343d40", fg="white", font=("Segoe UI", 10), image=settings_icon, compound="left", command=show_settings)
menu_btn_settings.grid(column=3, row=1, sticky="nsew")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

home_parent_frame = tk.Frame(root, bg="#273F4F")
home_parent_frame.pack(fill="both", expand=True)

home_child_frame = tk.Frame(home_parent_frame, bg="#eaeaf2")
home_child_frame.pack(fill="both", expand=True, padx=5, pady=5)

home_scrollable = ScrollableFrame(home_child_frame)
home_scrollable.pack(fill="both", expand=True, padx=10, pady=10)
home_body_frame = home_scrollable.scrollable_frame

about_frame_lbl = tk.LabelFrame(home_body_frame, text="About", font=("century gothic", 10, "bold"), bg="#eaeaf2", fg="#273F4F")
about_frame_lbl.pack(fill="x", padx=10, pady=(5, 5))

about_header_frame = tk.Frame(about_frame_lbl, bg="#eaeaf2")
about_header_frame.pack(fill="x", padx=10, pady=(5, 5))

about_header_lbl = tk.Label(about_header_frame, text="Welcome to Genesys Cloud Python Script", font=("century gothic", 14, "bold"), bg="#eaeaf2", fg="#000000")
about_header_lbl.pack(side="left")

about_sub_header_frame = tk.Frame(about_frame_lbl, bg="#eaeaf2")
about_sub_header_frame.pack(fill="x", padx=10, pady=(5, 5))

sub_header_txt = "  This tool provides a simple, user-friendly interface for extracting and reviewing essential information from your Genesys Cloud platform."

about_sub_header_lbl = tk.Label(about_sub_header_frame, text=sub_header_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000")
about_sub_header_lbl.pack(side="left")

key_features_frame_lbl = tk.LabelFrame(home_body_frame, text="Key Features", 
                                       font=("century gothic", 10, "bold"), 
                                       bg="#eaeaf2", fg="#273F4F")
key_features_frame_lbl.pack(fill="x", padx=10, pady=(5, 5))

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

key_features_1_frame = tk.Label(key_features_frame_lbl, bg="#eaeaf2")
key_features_1_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_1_lbl = tk.Label(key_features_1_frame, text="Agent Performance",
                         font=("century gothic", 12, "bold"), bg="#eaeaf2", fg="#000000")
key_features_1_lbl.pack(side="left")

key_features_1_description_frame = tk.Frame(key_features_frame_lbl, bg="#eaeaf2")
key_features_1_description_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_1_description_txt = "  Quickly retrieve and display user profiles, including full names, email addresses, and status."

key_features_1_description_lbl = tk.Label(key_features_1_description_frame, text=key_features_1_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000")

key_features_1_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

key_features_2_frame = tk.Label(key_features_frame_lbl, bg="#eaeaf2")
key_features_2_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_2_lbl = tk.Label(key_features_2_frame, text="Roles & Permission",
                         font=("century gothic", 12, "bold"), bg="#eaeaf2", fg="#000000")
key_features_2_lbl.pack(side="left")

key_features_2_description_frame = tk.Frame(key_features_frame_lbl, bg="#eaeaf2")
key_features_2_description_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_2_description_txt = "  Access a comprehensive breakdown of all user roles and their associated permissions across your organization."

key_features_2_description_lbl = tk.Label(key_features_2_description_frame, text=key_features_2_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000")

key_features_2_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

key_features_3_frame = tk.Label(key_features_frame_lbl, bg="#eaeaf2")
key_features_3_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_3_lbl = tk.Label(key_features_3_frame, text="Bulk: Add/Assign to Queues",
                         font=("century gothic", 12, "bold"), bg="#eaeaf2", fg="#000000")
key_features_3_lbl.pack(side="left")

key_features_3_description_frame = tk.Frame(key_features_frame_lbl, bg="#eaeaf2")
key_features_3_description_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_3_description_txt = "  This feature allows you to bulk add and assign Genesys queues."

key_features_3_description_lbl = tk.Label(key_features_3_description_frame, text=key_features_3_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000")

key_features_3_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

key_features_4_frame = tk.Label(key_features_frame_lbl, bg="#eaeaf2")
key_features_4_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_4_lbl = tk.Label(key_features_4_frame, text="Wrapup Codes",
                         font=("century gothic", 12, "bold"), bg="#eaeaf2", fg="#000000")
key_features_4_lbl.pack(side="left")

key_features_4_description_frame = tk.Frame(key_features_frame_lbl, bg="#eaeaf2")
key_features_4_description_frame.pack(fill="x", padx=10, pady=(5, 5))

key_features_4_description_txt = "  This feature allows you to bulk add and assign Genesys wrapup codes."

key_features_4_description_lbl = tk.Label(key_features_4_description_frame, text=key_features_4_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000")

key_features_4_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

how_it_works_frame_lbl = tk.LabelFrame(home_body_frame, text="How It Works", 
                                       font=("century gothic", 10, "bold"), 
                                       bg="#eaeaf2", fg="#273F4F")
how_it_works_frame_lbl.pack(fill="x", padx=10, pady=(5, 5))

how_it_works_1_description_frame = tk.Frame(how_it_works_frame_lbl, bg="#eaeaf2")
how_it_works_1_description_frame.pack(fill="x", padx=10, pady=(5, 5))

how_it_works_1_description_txt = "1. Navigate using the menu at the top."

how_it_works_1_description_lbl = tk.Label(how_it_works_1_description_frame, text=how_it_works_1_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000", wraplength=450)
how_it_works_1_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

how_it_works_2_description_frame = tk.Frame(how_it_works_frame_lbl, bg="#eaeaf2")
how_it_works_2_description_frame.pack(fill="x", padx=10, pady=(5, 5))

how_it_works_2_description_txt = "2. Select the desired function: either User Extraction, Roles & Permission, Bulk: Add and Assign Queues and Bulk: Add and Assign Wrapup Codes."

how_it_works_2_description_lbl = tk.Label(how_it_works_2_description_frame, text=how_it_works_2_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000", wraplength=450)
how_it_works_2_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

how_it_works_3_description_frame = tk.Frame(how_it_works_frame_lbl, bg="#eaeaf2")
how_it_works_3_description_frame.pack(fill="x", padx=10, pady=(5, 5))

how_it_works_3_description_txt = "3. The extracted data will be displayed in a structured format and can be saved as needed."

how_it_works_3_description_lbl = tk.Label(how_it_works_3_description_frame, text=how_it_works_3_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000", wraplength=450)
how_it_works_3_description_lbl.pack(side="left")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

note_frame_lbl = tk.LabelFrame(home_body_frame, text="Note", 
                                       font=("century gothic", 10, "bold"), 
                                       bg="#eaeaf2", fg="#273F4F")
note_frame_lbl.pack(fill="x", padx=10, pady=(5, 5))

note_description_frame = tk.Frame(note_frame_lbl, bg="#eaeaf2")
note_description_frame.pack(fill="x", padx=10, pady=(5, 5))

note_description_txt = "Please ensure you are authenticated with valid API credentials to access Genesys Cloud data. All operations comply with your organization's data security protocols."

note_description_lbl = tk.Label(note_description_frame, text=note_description_txt, font=("century gothic", 8), justify="left", bg="#eaeaf2", fg="#000000", wraplength=450)
note_description_lbl.pack(side="left")

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 

def show_agent_performance_tab():
    user_management_agent_performance_parent_frame.pack(fill="both", expand=True, padx=5, pady=5)
    user_management_roles_and_permission_parent_frame.forget()
    user_management_queue_parent_frame.forget()
    user_management_wrapup_codes_parent_frame.forget()

    user_menu_agent_performance_btn.config(font=("Segoe UI", 8, "bold"))
    user_menu_roles_and_permission_btn.config(font=("Segoe UI", 8))
    user_menu_queues_btn.config(font=("Segoe UI", 8))
    user_menu_wrap_up_codes_btn.config(font=("Segoe UI", 8))

def show_roles_and_permission_tab():
    user_management_agent_performance_parent_frame.forget()
    user_management_roles_and_permission_parent_frame.pack(fill="both", expand=True, padx=5, pady=5)
    user_management_queue_parent_frame.forget()
    user_management_wrapup_codes_parent_frame.forget()

    user_menu_agent_performance_btn.config(font=("Segoe UI", 8))
    user_menu_roles_and_permission_btn.config(font=("Segoe UI", 8, "bold"))
    user_menu_queues_btn.config(font=("Segoe UI", 8))
    user_menu_wrap_up_codes_btn.config(font=("Segoe UI", 8))

def show_queues_tab():
    user_management_agent_performance_parent_frame.forget()
    user_management_roles_and_permission_parent_frame.forget()
    user_management_queue_parent_frame.pack(fill="both", expand=True, padx=5, pady=5)
    user_management_wrapup_codes_parent_frame.forget()

    user_menu_agent_performance_btn.config(font=("Segoe UI", 8))
    user_menu_roles_and_permission_btn.config(font=("Segoe UI", 8))
    user_menu_queues_btn.config(font=("Segoe UI", 8, "bold"))
    user_menu_wrap_up_codes_btn.config(font=("Segoe UI", 8))

def show_wrap_up_codes_tab():
    user_management_agent_performance_parent_frame.forget()
    user_management_roles_and_permission_parent_frame.forget()
    user_management_queue_parent_frame.forget()
    user_management_wrapup_codes_parent_frame.pack(fill="both", expand=True, padx=5, pady=5)

    user_menu_agent_performance_btn.config(font=("Segoe UI", 8))
    user_menu_roles_and_permission_btn.config(font=("Segoe UI", 8))
    user_menu_queues_btn.config(font=("Segoe UI", 8))
    user_menu_wrap_up_codes_btn.config(font=("Segoe UI", 8, "bold"))

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

user_management_parent_frame = tk.Frame(root, bg="#273F4F")

user_management_menu_frame = tk.Frame(user_management_parent_frame, bg="#273F4F")
user_management_menu_frame.pack(fill="x", side="top", pady=(2, 0))

user_menu_agent_performance_btn = tk.Button(user_management_menu_frame, text=" Agent Performance ", border=0, bg="#273F4F", fg="white", compound="left", font=("Segoe UI", 8, "bold"), command=show_agent_performance_tab)
user_menu_agent_performance_btn.grid(column=1, row=1, sticky="nsew")

user_menu_roles_and_permission_btn = tk.Button(user_management_menu_frame, text=" Roles & Permission ", border=0, bg="#273F4F", fg="white", compound="left", font=("Segoe UI", 8), command=show_roles_and_permission_tab)
user_menu_roles_and_permission_btn.grid(column=2, row=1, sticky="nsew")

user_menu_queues_btn = tk.Button(user_management_menu_frame, text=" Queues ", border=0, bg="#273F4F", fg="white", compound="left", font=("Segoe UI", 8), command=show_queues_tab)
user_menu_queues_btn.grid(column=3, row=1, sticky="nsew")

user_menu_wrap_up_codes_btn = tk.Button(user_management_menu_frame, text=" Wrap-Up Codes ", border=0, bg="#273F4F", fg="white", compound="left", font=("Segoe UI", 8), command=show_wrap_up_codes_tab)
user_menu_wrap_up_codes_btn.grid(column=4, row=1, sticky="nsew")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

user_management_agent_performance_parent_frame = tk.Frame(user_management_parent_frame, bg="#eaeaf2")

user_management_agent_performance_child_frame = tk.LabelFrame(user_management_agent_performance_parent_frame, bg="#eaeaf2", fg="#343d40")
user_management_agent_performance_child_frame.pack(fill="x", padx=5, pady=(5, 0))

add_column_frame = tk.Frame(user_management_agent_performance_child_frame, bg="#eaeaf2")
add_column_frame.pack(fill="x", padx=5, pady=5)

status_lbl = tk.Label(add_column_frame, text="State: ", font=("Segoe UI", 10))
status_lbl.pack(side="left")

user_state_var = tk.StringVar()
user_state = ttk.Combobox(add_column_frame, textvariable=user_state_var, font=("Segoe UI", 10), justify="center", state="readonly")
user_state["values"] = ("Active", "Inactive", "Deleted", "Any")
user_state.current(3)
user_state.pack(side="left")

user_state.bind("<<ComboboxSelected>>", on_selection)  

generate_user_list_btn = tk.Button(add_column_frame, text=" Export ", font=("Segoe UI", 10), command=generate_user_list)
generate_user_list_btn.pack(side="right")

add_column_btn = tk.Button(add_column_frame, text=" + ", width=3, font=("Segoe UI", 10), command=show_checkbox)
add_column_btn.pack(side="right", padx=(0, 5)) 

separator = tk.Frame(user_management_agent_performance_child_frame, bg="#eaeaf2", height=1)
separator.pack(fill="x", pady=0)

checkbox_frame = tk.Frame(user_management_agent_performance_child_frame, bg="#eaeaf2")

checkbox_var = {}

items = ["ID", "Name", "Email", "State", "Licenses", "Roles", "Division", "Department", "ACDAutoAnswer", "LastLogin", "Queues"]

# Add checkboxes in 5 columns
for index, item in enumerate(items):
    var = tk.BooleanVar()
    if item in ["Name", "State"]:
        var.set(True)

    checkbox = tk.Checkbutton(checkbox_frame, text=item, variable=var, bg="#eaeaf2", anchor="w")
    row = index // 5
    col = index % 5
    checkbox.grid(row=row, column=col, sticky="w", padx=20, pady=5)

    checkbox_var[item] = var

# Calculate the row after the last checkbox row
last_row = (len(items) + 4) // 5

buttons_frame = tk.Frame(checkbox_frame, bg="#eaeaf2")
buttons_frame.grid(row=last_row + 1, column=0, columnspan=5, sticky="e", padx=10, pady=(10, 5))

done_btn = tk.Button(buttons_frame, text=" Add ", width=10, command=hide_listbox)
done_btn.pack(side="right", padx=(5, 0))

def reset_default_view():
    setup_treeview(user_body_frame, ["Name", "State"])

    for item, var in checkbox_var.items():
        if item in ["Name", "State"]:
            var.set(True)
        else:
            var.set(False)

    checkbox_frame.forget()
    add_column_btn.config(state="active")
    separator.config(bg="#eaeaf2")

clear_btn = tk.Button(buttons_frame, text=" Clear ", width=10, command=reset_default_view)
clear_btn.pack(side="right", padx=(0, 5))

user_body_frame = tk.LabelFrame(user_management_agent_performance_parent_frame, bg="#eaeaf2", text="", font=("Segoe UI", 10))
user_body_frame.pack(fill="both", expand=True, padx=5, pady=5)

user_tree = None
setup_treeview(user_body_frame, ["Name", "State"])

user_footer_frame = tk.LabelFrame(user_management_agent_performance_parent_frame, bg="#eaeaf2", text="", font=("Segoe UI", 10))

user_tree_output_frame = tk.Frame(user_footer_frame, bg="#eaeaf2")
user_tree_output_frame.pack(fill="x", padx=5, pady=5)

user_tree_output_lbl = tk.Label(user_tree_output_frame, bg="#eaeaf2", text="", font=("Segoe UI", 10))
user_tree_output_lbl.pack(fill="x")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

user_management_roles_and_permission_parent_frame = tk.Frame(user_management_parent_frame, bg="#273F4F")

user_management_roles_and_permission_child_frame = tk.Frame(user_management_roles_and_permission_parent_frame, bg="#eaeaf2")
user_management_roles_and_permission_child_frame.pack(fill="both", expand=True)

user_id_frame = tk.LabelFrame(user_management_roles_and_permission_child_frame, bg="#eaeaf2")
user_id_frame.pack(fill="x", padx=5, pady=5)

user_id_lbl = tk.Label(user_id_frame, text="User Id: ", font=("Segoe UI", 10))
user_id_lbl.pack(side="left", padx=(5, 0), pady=5)

user_id_entry = tk.Entry(user_id_frame, width=30, font=("Segoe UI", 10))
user_id_entry.pack(side="left", pady=5)

export_roles_and_permission_btn = tk.Button(user_id_frame, text=" Export ", font=("Segoe UI", 10), command=get_roles_and_permissions)
export_roles_and_permission_btn.pack(side="right", padx=5, pady=5)

roles_and_permission_table_frame = tk.LabelFrame(user_management_roles_and_permission_child_frame, bg="#eaeaf2")
roles_and_permission_table_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))

roles_and_permission_column = ("Role ID", "Role Name", "Role Description", "Domain", "Entity Name", "Actions")
roles_and_permission_table = ttk.Treeview(roles_and_permission_table_frame, columns=roles_and_permission_column, show="headings", height=20, selectmode="browse")

for col in roles_and_permission_column:
    roles_and_permission_table.heading(col, text=col, anchor="center")
    roles_and_permission_table.column(col, anchor="center", width=120)

roles_and_permission_table.pack(fill="both", expand=True, padx=5, pady=5)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

user_management_queue_parent_frame = tk.Frame(user_management_parent_frame, bg="#273F4F")
user_management_queue_child_frame = tk.Frame(user_management_queue_parent_frame, bg="#eaeaf2")
user_management_queue_child_frame.pack(fill="both", expand=True)

queue_bulk_queue_creation_frame = tk.LabelFrame(user_management_queue_child_frame, bg="#eaeaf2", fg="#273F4F", text=" BULK: ADD QUEUE ", font=("Segoe UI", 8, "bold italic"))
queue_bulk_queue_creation_frame.pack(fill="x", padx=5, pady=5)

bulk_add_new_queue_lbl = tk.Label(queue_bulk_queue_creation_frame, text="Import File: ", font=("Segoe UI", 8))
bulk_add_new_queue_lbl.pack(side="left", padx=(5, 0), pady=5)

bulk_add_new_queue_btn = tk.Button(queue_bulk_queue_creation_frame, text=" Select File ", font=("Segoe UI", 8), command=bulk_add_queue)
bulk_add_new_queue_btn.pack(side="left", pady=5)

queue_bulk_assignment_frame = tk.LabelFrame(user_management_queue_child_frame, bg="#eaeaf2", fg="#273F4F", text=" BULK: USER ASSIGNMENT ", font=("Segoe UI", 8, "bold italic"))
queue_bulk_assignment_frame.pack(fill="x", padx=5, pady=5)

bulk_user_assignment_lbl = tk.Label(queue_bulk_assignment_frame, text="Import File: ", font=("Segoe UI", 8))
bulk_user_assignment_lbl.pack(side="left", padx=(5, 0), pady=5)

bulk_user_assignment_btn = tk.Button(queue_bulk_assignment_frame, text=" Select File ", font=("Segoe UI", 8), command=bulk_assign_queue)
bulk_user_assignment_btn.pack(side="left", pady=5)

all_queues_table_frame = tk.LabelFrame(user_management_queue_child_frame, bg="#eaeaf2", fg="#273F4F",text=" QUEUE DETAILS ", font=("Segoe UI", 8, "bold italic"))
all_queues_table_frame.pack(fill="x", padx=5, pady=5)

refresh_button_frame = tk.Frame(all_queues_table_frame, bg="#eaeaf2")
refresh_button_frame.pack(fill="x")

refresh_btn = tk.Button(refresh_button_frame, text=" Refresh ", font=("Segoe UI", 8), command=refresh_queue_table)
refresh_btn.pack(side="right", padx=5)

export_queue_btn = tk.Button(refresh_button_frame, text=" Export ", font=("Segoe UI", 8), command=export_queues)
export_queue_btn.pack(side="right", padx=5) 

queues_column = ("Queue Id", "Queue Name", "Division", "Date Created", "Created By", "Member Count")
queues_table = ttk.Treeview(all_queues_table_frame, columns=queues_column, show="headings", height=20, selectmode="browse")

for col in queues_column:
    queues_table.heading(col, text=col, anchor="center")
    queues_table.column(col, anchor="center", width=120)

queues_table.pack(fill="both", expand=True, padx=5, pady=5)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

user_management_wrapup_codes_parent_frame = tk.Frame(user_management_parent_frame, bg="#273F4F")
user_management_wrapup_codes_child_frame = tk.Frame(user_management_wrapup_codes_parent_frame, bg="#eaeaf2")
user_management_wrapup_codes_child_frame.pack(fill="both", expand=True)

bulk_add_wrapup_codes_frame = tk.LabelFrame(user_management_wrapup_codes_child_frame, bg="#eaeaf2", fg="#273F4F", text=" BULK: ADD WRAPUP CODES ", font=("Segoe UI", 8, "bold italic"))
bulk_add_wrapup_codes_frame.pack(fill="x", padx=5, pady=5)

bulk_add_wrapup_codes_lbl = tk.Label(bulk_add_wrapup_codes_frame,text="Import File: ",font=("Segoe UI", 8))
bulk_add_wrapup_codes_lbl.pack(side="left", padx=(5, 0), pady=5)

bulk_add_wrapup_codes_btn = tk.Button(bulk_add_wrapup_codes_frame,text=" Select File ",font=("Segoe UI", 8),command=bulk_add_wrap_up)
bulk_add_wrapup_codes_btn.pack(side="left", pady=5)  # remove padx

bulk_wrapup_assignment_frame = tk.LabelFrame(user_management_wrapup_codes_child_frame, bg="#eaeaf2",fg="#273F4F",text=" BULK: WRAPUP CODE ASSIGNMENT ",font=("Segoe UI", 8, "bold italic"))
bulk_wrapup_assignment_frame.pack(fill="x", padx=5, pady=5)

bulk_wrapup_assignment_lbl = tk.Label(bulk_wrapup_assignment_frame,text="Import File: ",font=("Segoe UI", 8))
bulk_wrapup_assignment_lbl.pack(side="left", padx=(5, 0), pady=5)

bulk_wrapup_assignment_btn = tk.Button(bulk_wrapup_assignment_frame,text=" Select File ",font=("Segoe UI", 8), command=bulk_assign_wrapup)
bulk_wrapup_assignment_btn.pack(side="left", pady=5)

all_wrapup_table_frame = tk.LabelFrame(user_management_wrapup_codes_child_frame, bg="#eaeaf2", fg="#273F4F",text=" WRAP UP CODE DETAILS ", font=("Segoe UI", 8, "bold italic"))
all_wrapup_table_frame.pack(fill="x", padx=5, pady=5)

refresh_button_frame = tk.Frame(all_wrapup_table_frame, bg="#eaeaf2")
refresh_button_frame.pack(fill="x")

refresh_btn = tk.Button(refresh_button_frame, text=" Refresh ", font=("Segoe UI", 8), command=refresh_wrapup_table)
refresh_btn.pack(side="right", padx=5)

export_wrapup_btn = tk.Button(refresh_button_frame, text=" Export ", font=("Segoe UI", 8), command=export_wrapup_codes)
export_wrapup_btn.pack(side="right", padx=5)

wrapup_codes_column = ("Wrapup ID", "Wrapup Name", "Division", "Date Created", "Created By")
wrapup_codes_table = ttk.Treeview(all_wrapup_table_frame, columns=wrapup_codes_column, show="headings", height=20, selectmode="browse")

for col in wrapup_codes_column:
    wrapup_codes_table.heading(col, text=col, anchor="center")
    wrapup_codes_table.column(col, anchor="center", width=120)

wrapup_codes_table.pack(fill="both", expand=True, padx=5, pady=5)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

settings_parent_frame = tk.Frame(root, bg="#273F4F")
settings_child_frame = tk.Frame(settings_parent_frame, bg="#eaeaf2")
settings_child_frame.pack(fill="both", expand=True, padx=5, pady=5)

settings_header_frame = tk.LabelFrame(settings_child_frame,  bg="#eaeaf2", fg="#273F4F", text=" Client Credentials ", font=("Segoe UI", 10, "bold"))
settings_header_frame.pack(fill="x", padx=5, pady=5)

client_id_frame = tk.Frame(settings_header_frame,  bg="#eaeaf2")
client_id_frame.pack(fill="x", padx=5, pady=(10, 5))

client_id_lbl = tk.Label(client_id_frame, bg="#eaeaf2", text="Client Id: ", font=("Segoe UI", 8))
client_id_lbl.pack(side="left")

client_id_entry = tk.Entry(client_id_frame, bg="#eaeaf2", font=("Segoe UI", 8), show="*", width=40)
client_id_entry.pack(side="right")

client_secret_frame = tk.Frame(settings_header_frame, bg="#eaeaf2")
client_secret_frame.pack(fill="x", padx=5, pady=(0, 5))

client_secret_lbl = tk.Label(client_secret_frame, bg="#eaeaf2", text="Client Secret: ", font=("Segoe UI", 8))
client_secret_lbl.pack(side="left")

client_secret_entry = tk.Entry(client_secret_frame, bg="#eaeaf2", font=("Segoe UI", 8), show="*", width=40)
client_secret_entry.pack(side="right")

save_settings_frame = tk.Frame(settings_header_frame, bg="#eaeaf2")
save_settings_frame.pack(fill="x", padx=5, pady=5)

def toggle_save_button(*args):
    if client_id_entry.get().strip() and client_secret_entry.get().strip():
        test_oauth_credentials_btn.config(state="normal")
    else:
        test_oauth_credentials_btn.config(state="disabled")
        show_organization_info_frame.forget()

client_id_entry.bind("<KeyRelease>", toggle_save_button)
client_secret_entry.bind("<KeyRelease>", toggle_save_button)

test_oauth_credentials_btn = tk.Button(save_settings_frame, text=" Authenticate ", font=("Segoe UI", 8), width=15, command=get_org_details, state="disabled")
test_oauth_credentials_btn.pack(side="right", padx=5)

show_organization_info_frame = tk.LabelFrame(settings_child_frame, bg="#eaeaf2", fg="#273F4F", text=" Organization Information ", font=("Segoe UI", 10, "bold"))

org_id_frame = tk.Frame(show_organization_info_frame, bg="#eaeaf2")
org_id_frame.pack(fill="x", padx=5, pady=5)

org_id_lbl = tk.Label(org_id_frame, bg="#eaeaf2", text=" Organization ID: ", font=("Segoe UI", 8))
org_id_lbl.pack(side="left")

org_id_value = tk.Label(org_id_frame, bg="#eaeaf2", text="")
org_id_value.pack(side="left")

org_name_frame = tk.Frame(show_organization_info_frame, bg="#eaeaf2")
org_name_frame.pack(fill="x", padx=5, pady=5)

org_name_lbl = tk.Label(org_name_frame, bg="#eaeaf2", text=" Organization Name: ", font=("Segoe UI", 8))
org_name_lbl.pack(side="left")

org_name_value = tk.Label(org_name_frame, bg="#eaeaf2", text="")
org_name_value.pack(side="left")

org_domain_frame = tk.Frame(show_organization_info_frame, bg="#eaeaf2")
org_domain_frame.pack(fill="x", padx=5, pady=5)

org_domain_lbl = tk.Label(org_domain_frame, bg="#eaeaf2", text=" Organization Domain: ", font=("Segoe UI", 8))   
org_domain_lbl.pack(side="left")

org_domain_value = tk.Label(org_domain_frame, bg="#eaeaf2", text="")
org_domain_value.pack(side="left")

root.mainloop()