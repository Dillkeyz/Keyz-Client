import minecraft_launcher_lib as mc
import subprocess
import customtkinter as ctk
import json
import os
import urllib.request  # For downloading files
import xml.etree.ElementTree as ET  # For parsing Maven metadata XML
from PIL import Image  # Import Image from PIL

# New imports for Azure auth
import msal
import requests
import tkinter.messagebox as messagebox
import webbrowser  # To open browser windows

# Global variable to store authentication tokens
auth_tokens = None
sign_out_button = None  # Global sign-out button (None when not signed in)

def azure_authenticate():
    CLIENT_ID = "e9662c65-b293-425d-bc6e-953440070365"  # Your Azure app ID
    TENANT_ID = "2e0ab107-6bbb-4d2c-ba24-15d2d3702e31"
    AUTHORITY = "https://login.microsoftonline.com/consumers"  # Consider using "common" if needed
    redirect_uri="http://localhost:8080//callback"  # This should match the registered URI
    SCOPE = ["XboxLive.signin"]

    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
    result = app.acquire_token_interactive(scopes=SCOPE)

    # Retrieve the access token instead of id_token
    access_token = result.get("access_token")
    if not access_token:
        messagebox.showerror("Authentication Error", f"Failed to acquire access token: {result.get('error_description', 'Unknown error')}")
        return None

    # Step 1: Authenticate with Xbox Live using the access token.
    xbox_auth_url = "https://user.auth.xboxlive.com/user/authenticate"
    xbox_payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={access_token}"
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    xbox_response = requests.post(xbox_auth_url, json=xbox_payload)
    if xbox_response.status_code != 200:
        messagebox.showerror("Xbox Authentication Failed", f"Error {xbox_response.status_code}: {xbox_response.text}")
        return None

    xbox_data = xbox_response.json()
    xbox_token = xbox_data["Token"]
    userhash = xbox_data["DisplayClaims"]["xui"][0]["uhs"]

    # Step 2: Get XSTS Token
    xsts_url = "https://xsts.auth.xboxlive.com/xsts/authorize"
    xsts_payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbox_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    xsts_response = requests.post(xsts_url, json=xsts_payload)
    if xsts_response.status_code != 200:
        messagebox.showerror("XSTS Authorization Failed", f"Error {xsts_response.status_code}: {xsts_response.text}")
        return None

    xsts_data = xsts_response.json()
    xsts_token = xsts_data["Token"]

    # Step 3: Authenticate with Minecraft
    mc_auth_url = "https://api.minecraftservices.com/authentication/login_with_xbox"
    mc_payload = {"identityToken": f"XBL3.0 x={userhash};{xsts_token}"}

    mc_response = requests.post(mc_auth_url, json=mc_payload)
    if mc_response.status_code != 200:
        messagebox.showerror("Minecraft Authentication Failed", f"Error {mc_response.status_code}: {mc_response.text}")
        return None

    mc_data = mc_response.json()
    mc_access_token = mc_data["access_token"]

    # Step 4: Get Minecraft Profile
    mc_profile_url = "https://api.minecraftservices.com/minecraft/profile"
    headers = {"Authorization": f"Bearer {mc_access_token}"}
    mc_profile_response = requests.get(mc_profile_url, headers=headers)

    if mc_profile_response.status_code != 200:
        messagebox.showerror("Profile Error", f"Error {mc_profile_response.status_code}: {mc_profile_response.text}")
        return None

    mc_profile_data = mc_profile_response.json()
    username = mc_profile_data["name"]
    uuid = mc_profile_data["id"]

    messagebox.showinfo("Authentication Success", f"Signed in as {username}!")

    return {
        "microsoft_access_token": id_token,
        "xbox_token": xbox_token,
        "xsts_token": xsts_token,
        "minecraft_access_token": mc_access_token,
        "username": username,
        "uuid": uuid
    }

def sign_in_with_microsoft():
    """
    Calls azure_authenticate and stores the returned tokens globally.
    Once signed in, updates the profile label, removes the sign in button,
    and creates a sign out button.
    """
    global auth_tokens, ms_auth_button, profile_status_label, sign_out_button, root
    tokens = azure_authenticate()
    if tokens:
        auth_tokens = tokens
        profile_status_label.configure(text=f"Signed in as: {auth_tokens['username']}")
        ms_auth_button.destroy()  # Remove sign in button
        # Create the Sign Out button below the profile status label
        sign_out_button = ctk.CTkButton(root, text="Sign Out", command=sign_out, font=("Arial", 12))
        sign_out_button.place(relx=0.7, rely=0.48, anchor="center")
        root.update_idletasks()
        print("DEBUG: auth_tokens set to", auth_tokens)

def sign_out():
    """
    Clears the authentication tokens, updates the profile status label,
    recreates the Microsoft Sign In button, and clears the browser session.
    """
    global auth_tokens, ms_auth_button, profile_status_label, sign_out_button, root
    auth_tokens = None
    profile_status_label.configure(text="Not signed in")
    # Recreate the Microsoft Sign In button
    ms_auth_button = ctk.CTkButton(root, text="Microsoft Sign In", command=sign_in_with_microsoft, font=("Arial", 12))
    ms_auth_button.place(relx=0.7, rely=0.42, anchor="center")
    # Destroy the Sign Out button if it exists
    if sign_out_button:
        sign_out_button.destroy()
    root.update_idletasks()
    # Open the Microsoft logout URL in the default browser to clear the session
    webbrowser.open("https://login.microsoftonline.com/common/oauth2/v2.0/logout")
    print("DEBUG: Signed out; auth_tokens reset.")

def get_latest_fabric_installer_version():
    """
    Fetches the latest Fabric installer version from Maven metadata.
    Returns the version string if successful, or None on error.
    """
    metadata_url = "https://maven.fabricmc.net/net/fabricmc/fabric-installer/maven-metadata.xml"
    try:
        with urllib.request.urlopen(metadata_url) as response:
            data = response.read()
            root_xml = ET.fromstring(data)
            release = root_xml.find("versioning/release")
            if release is not None and release.text:
                return release.text
            latest = root_xml.find("versioning/latest")
            if latest is not None and latest.text:
                return latest.text
    except Exception as e:
        print("Error fetching Fabric installer metadata:", e)
    return None

def download_fabric_installer():
    """
    Downloads the Fabric installer jar automatically.
    Returns the local path to the installer jar.
    """
    version = get_latest_fabric_installer_version()
    if version is None:
        version = "0.11.3"
        print("Falling back to default Fabric installer version:", version)
    installer_filename = f"fabric-installer-{version}.jar"
    installer_path = installer_filename
    if not os.path.exists(installer_path):
        url = f"https://maven.fabricmc.net/net/fabricmc/fabric-installer/{version}/{installer_filename}"
        print("Downloading Fabric installer from:", url)
        try:
            urllib.request.urlretrieve(url, installer_path)
            print("Downloaded Fabric installer.")
        except Exception as e:
            print("Error downloading Fabric installer:", e)
    else:
        print("Fabric installer already exists locally.")
    return installer_path

def ensure_launcher_profiles():
    """
    Ensures a minimal launcher_profiles.json exists in the Minecraft directory.
    """
    launcher_profiles_path = os.path.join(minecraft_directory, "launcher_profiles.json")
    if not os.path.exists(launcher_profiles_path):
        print("launcher_profiles.json not found. Creating a minimal profile file.")
        try:
            with open(launcher_profiles_path, "w") as f:
                f.write('{"profiles": {}}')
        except Exception as e:
            print("Error creating launcher_profiles.json:", e)

def is_version_working(version):
    """
    Checks if the jar file for a vanilla version exists.
    """
    jar_path = os.path.join(minecraft_directory, "versions", version, f"{version}.jar")
    return os.path.exists(jar_path)

def is_fabric_working(selected_version):
    """
    Checks if a Fabric installation for the given version is working
    by verifying that its jar file exists.
    """
    folder, json_file, jar_file = find_fabric_version_folder(selected_version)
    return jar_file is not None and os.path.exists(jar_file)

def has_fabric_profile(selected_version):
    """
    Returns True if a Fabric version folder exists for the selected version.
    """
    return is_fabric_working(selected_version)

def create_fabric_profile(selected_version):
    """
    Creates a Fabric profile in launcher_profiles.json if one does not exist.
    The profile id is "fabric-loader-<selected_version>".
    """
    launcher_profiles_path = os.path.join(minecraft_directory, "launcher_profiles.json")
    profile_id = f"fabric-loader-{selected_version}"
    try:
        profiles_data = {}
        if os.path.exists(launcher_profiles_path):
            with open(launcher_profiles_path, "r") as f:
                profiles_data = json.load(f)
        else:
            profiles_data = {"profiles": {}}
        profiles = profiles_data.get("profiles", {})
        if profile_id not in profiles:
            profiles[profile_id] = {
                "name": f"Fabric {selected_version}",
                "lastVersionId": profile_id,
                "type": "custom"
            }
            profiles_data["profiles"] = profiles
            with open(launcher_profiles_path, "w") as f:
                json.dump(profiles_data, f, indent=4)
            print("Created new Fabric profile:", profile_id)
        else:
            print("Fabric profile already exists:", profile_id)
    except Exception as e:
        print("Error updating launcher_profiles.json:", e)

def find_fabric_version_folder(selected_version):
    """
    Checks the versions folder for a Fabric loader folder that corresponds to selected_version.
    Returns (folder_path, json_file, jar_file) if found; otherwise, returns (None, None, None).
    """
    versions_dir = os.path.join(minecraft_directory, "versions")
    for folder in os.listdir(versions_dir):
        if folder.startswith("fabric-loader"):
            json_file = os.path.join(versions_dir, folder, f"{folder}.json")
            if os.path.exists(json_file):
                try:
                    with open(json_file, "r") as f:
                        data = json.load(f)
                    if selected_version in data.get("id", "") or selected_version == data.get("inheritsFrom", ""):
                        jar_file = os.path.join(versions_dir, folder, f"{folder}.jar")
                        return os.path.join(versions_dir, folder), json_file, jar_file
                except Exception as e:
                    print("Error reading Fabric version JSON from", json_file, e)
    return None, None, None

def get_working_vanilla_versions():
    """
    Uses the launcher library to get installed vanilla versions,
    and returns only those versions whose jar file exists.
    """
    vanilla_versions = mc.utils.get_installed_versions(minecraft_directory)
    working_versions = set()
    for ver in vanilla_versions:
        ver_id = ver["id"]
        if is_version_working(ver_id):
            working_versions.add(ver_id)
    return working_versions

def get_version_options():
    """
    Builds a list of (version, loader_mode) tuples based on working installed versions.
    For each working vanilla version, add the vanilla option.
    If a Fabric installation is working for that version, also add the Fabric option.
    """
    options = []
    working_versions = get_working_vanilla_versions()
    for ver in working_versions:
        options.append((ver, "vanilla"))
        if is_fabric_working(ver):
            options.append((ver, "fabric"))
    return options

def get_custom_profiles():
    """
    Reads launcher_profiles.json and returns a list of custom profiles whose version jar exists.
    Each profile is returned as a dictionary with keys:
      - profile_id
      - name
      - lastVersion (the version it launches)
    Only profiles with working versions are added.
    """
    profiles = []
    launcher_profiles_path = os.path.join(minecraft_directory, "launcher_profiles.json")
    if os.path.exists(launcher_profiles_path):
        try:
            with open(launcher_profiles_path, "r") as f:
                data = json.load(f)
            for profile_id, profile in data.get("profiles", {}).items():
                last_version = profile.get("lastVersionId", "")
                if last_version:
                    # For Fabric profiles, check Fabric working; otherwise check vanilla.
                    if "fabric-loader" in profile_id:
                        if not is_fabric_working(last_version):
                            continue
                    else:
                        if not is_version_working(last_version):
                            continue
                    profiles.append({
                        "profile_id": profile_id,
                        "name": profile.get("name", profile_id),
                        "lastVersion": last_version
                    })
        except Exception as e:
            print("Error reading custom profiles:", e)
    return profiles

# Get Minecraft directory and available version info
minecraft_directory = mc.utils.get_minecraft_directory()
all_ver_info = mc.utils.get_available_versions(minecraft_directory)

# File to save user settings
USER_DATA_FILE = "user_data.json"

def save_settings(username, dark_mode, last_version, loader_mode):
    with open(USER_DATA_FILE, "w") as f:
        json.dump({"username": username, "dark_mode": dark_mode, "last_version": last_version, "loader_mode": loader_mode}, f)

def load_settings():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            data = json.load(f)
            return (data.get("username", ""), data.get("dark_mode", False),
                    data.get("last_version", ""), data.get("loader_mode", "vanilla"))
    return "", False, "", "vanilla"

# -----------------------------
# Vanilla Minecraft installation and launch
# -----------------------------
def install_version():
    ver = version_var.get()
    install_button.configure(text="Installing", state="disabled")
    mc.install.install_minecraft_version(ver, minecraft_directory)
    launch_vanilla_version()

def launch_vanilla_version():
    print("DEBUG: launch_vanilla_version auth_tokens =", auth_tokens)  # Debug print
    # Ensure the user is signed in
    if not auth_tokens or "minecraft_access_token" not in auth_tokens:
        messagebox.showerror("Authentication Required", "Please sign in with Microsoft before launching.")
        return

    username = auth_tokens["username"]
    uuid = auth_tokens["uuid"]
    ver = version_var.get()
    save_settings(username, dark_mode_var.get(), ver, loader_mode.get())
    token = auth_tokens["minecraft_access_token"]

    setting = {
        "username": username,
        "uuid": uuid,
        "token": token,
    }
    minecraft_command = mc.command.get_minecraft_command(ver, minecraft_directory, setting)
    root.destroy()
    subprocess.run(minecraft_command)
    main()

# -----------------------------
# Fabric Minecraft installation and launch
# -----------------------------
def install_fabric_version():
    ver = version_var.get()
    install_button.configure(text="Installing Fabric", state="disabled")
    ensure_launcher_profiles()
    fabric_installer_path = download_fabric_installer()
    command = [
        "java", "-Xmx5G", "--add-opens", "java.base/java.lang=ALL-UNNAMED", "-jar", fabric_installer_path,
        "client",
        "-dir", minecraft_directory,
        "-mcversion", ver,
        "-downloadMinecraft"
    ]
    subprocess.run(command)
    launch_fabric_version()

def build_fabric_classpath(libraries, minecraft_dir):
    classpath_entries = []
    for lib in libraries:
        try:
            group, name, version = lib["name"].split(":")
        except Exception:
            continue
        lib_path = os.path.join(
            minecraft_dir, "libraries",
            group.replace(".", os.sep),
            name,
            version,
            f"{name}-{version}.jar"
        )
        if os.path.exists(lib_path):
            classpath_entries.append(lib_path)
    return os.pathsep.join(classpath_entries)

def launch_fabric_version():
    print("DEBUG: launch_fabric_version auth_tokens =", auth_tokens)  # Debug print
    # Ensure the user is signed in
    if not auth_tokens or "minecraft_access_token" not in auth_tokens:
        messagebox.showerror("Authentication Required", "Please sign in with Microsoft before launching.")
        return

    username = auth_tokens["username"]
    uuid = auth_tokens["uuid"]
    token = auth_tokens["minecraft_access_token"]
    ver = version_var.get()
    save_settings(username, dark_mode_var.get(), ver, loader_mode.get())
    
    fabric_folder, json_file, jar_file = find_fabric_version_folder(ver)
    if not json_file or not os.path.exists(json_file):
        print(f"Error: Could not find Fabric installation for Minecraft {ver}. Please reinstall Fabric.")
        return
    try:
        with open(json_file, 'r') as f:
            fabric_data = json.load(f)
    except Exception as e:
        print("Error loading Fabric JSON:", e)
        return

    profile_id = f"fabric-loader-{ver}"
    create_fabric_profile(ver)
    main_class = fabric_data.get("mainClass")
    libraries = fabric_data.get("libraries", [])
    classpath = build_fabric_classpath(libraries, minecraft_directory)
    classpath = os.pathsep.join([classpath, jar_file])
    vanilla_version = fabric_data.get("inheritsFrom", ver)
    vanilla_jar = os.path.join(minecraft_directory, "versions", vanilla_version, f"{vanilla_version}.jar")
    if os.path.exists(vanilla_jar):
        classpath = os.pathsep.join([classpath, vanilla_jar])
    else:
        print("Warning: Vanilla jar not found:", vanilla_jar)
    command = [
        "java",
        "-cp", classpath,
        main_class,
        "--version", profile_id,
        "--gameDir", minecraft_directory,
        "--username", username,
        "--uuid", uuid,
        "--accessToken", token
    ]
    root.destroy()
    subprocess.run(command)
    main()

# -----------------------------
# Combined launch function based on selected loader mode
# -----------------------------
def launch_version():
    if loader_mode.get() == "fabric":
        launch_fabric_version()
    else:
        launch_vanilla_version()

def check_installed():
    ver = version_var.get()
    if loader_mode.get() == "fabric":
        if is_fabric_working(ver):
            install_button.configure(text="Play (Fabric)", command=launch_version)
        else:
            install_button.configure(text="Install Fabric", command=install_fabric_version)
    else:
        if ver in get_working_vanilla_versions():
            install_button.configure(text="Play", command=launch_version)
        else:
            install_button.configure(text="Install", command=install_version)

def toggle_dark_mode():
    current_mode = dark_mode_var.get()
    if current_mode:
        ctk.set_appearance_mode("light")
        dark_mode_button.configure(text="D")
    else:
        ctk.set_appearance_mode("dark")
        dark_mode_button.configure(text="L")
    dark_mode_var.set(not current_mode)
    save_settings("", dark_mode_var.get(), version_var.get(), loader_mode.get())

def select_version(selected_ver, mode, popup_window):
    version_var.set(selected_ver)
    loader_mode.set(mode)
    current_version_label.configure(text=f"Selected: {selected_ver} ({mode})")
    popup_window.destroy()
    check_installed()

def show_version_popup():
    """Displays a fixed-size, modal popup with version options detected from the launcher."""
    popup = ctk.CTkToplevel(root)
    popup.title("Change Version")
    popup.geometry("300x400")
    popup.resizable(False, False)
    popup.transient(root)
    popup.grab_set()
    popup.focus_force()
    
    ctk.CTkLabel(popup, text="Select a version", font=("Arial", 16, "bold")).pack(pady=10)
    
    # Build standard version options from working vanilla versions
    options = get_version_options()
    if options:
        for ver, mode in options:
            btn = ctk.CTkButton(
                popup,
                text=f"{ver} ({mode})",
                command=lambda v=ver, m=mode: select_version(v, m, popup)
            )
            btn.pack(pady=3, padx=10, fill="x")
    else:
        ctk.CTkLabel(popup, text="No installed versions found.", font=("Arial", 14)).pack(pady=10)
    
    cancel_btn = ctk.CTkButton(popup, text="Cancel", command=popup.destroy)
    cancel_btn.pack(pady=10)

def main():
    global root, version_var, install_button, dark_mode_var, dark_mode_button, current_version_label, loader_mode, ms_auth_button, profile_status_label

    ctk.set_default_color_theme("green")
    
    root = ctk.CTk()
    root.title("Dillkeyz Client")
    root.geometry("800x500")
    root.resizable(False, False)

    saved_username, saved_dark_mode, saved_version, saved_loader = load_settings()
    
    # No username text box; sign in is handled via Microsoft.
    version_var = ctk.StringVar(value=saved_version if saved_version else (next(iter(get_working_vanilla_versions()), "1.16.1")))
    dark_mode_var = ctk.BooleanVar(value=saved_dark_mode)
    loader_mode = ctk.StringVar(value=saved_loader)
    
    if saved_dark_mode:
        ctk.set_appearance_mode("dark")
        dark_mode_button_text = "L"
    else:
        ctk.set_appearance_mode("light")
        dark_mode_button_text = "D"

    left_panel = ctk.CTkFrame(root, width=400, height=500, fg_color="transparent")
    left_panel.place(relx=0, rely=0, anchor="nw")
    try:
        original_image = Image.open("Client\\Config\\Logs\\Assets\\Leftbg.png")
        image = ctk.CTkImage(light_image=original_image, size=original_image.size)
        image_label = ctk.CTkLabel(left_panel, image=image, text="")  
        image_label.place(relx=0.5, rely=0.5, anchor="center")
    except Exception as e:
        print("Error loading background image:", e)

    title_label = ctk.CTkLabel(root, text="Dillkeyz Client", font=("Arial", 30, "bold"), fg_color="transparent", bg_color="transparent")
    title_label.place(relx=0.7, rely=0.2, anchor="center")

    # Profile status label displays sign in state
    profile_status_label = ctk.CTkLabel(root, text="Not signed in", font=("Arial", 14))
    profile_status_label.place(relx=0.7, rely=0.35, anchor="center")

    # Microsoft Sign In button
    ms_auth_button = ctk.CTkButton(root, text="Microsoft Sign In", command=sign_in_with_microsoft, font=("Arial", 12))
    ms_auth_button.place(relx=0.7, rely=0.42, anchor="center")

    dark_mode_button = ctk.CTkButton(root, text=dark_mode_button_text, command=toggle_dark_mode, width=50, height=50, font=("Arial", 20))
    dark_mode_button.place(relx=0.95, rely=0.07, anchor="center")

    current_version_label = ctk.CTkLabel(root, text=f"Selected: {version_var.get()} ({loader_mode.get()})", font=("Arial", 16))
    current_version_label.place(relx=0.7, rely=0.5, anchor="center")
    
    change_version_button = ctk.CTkButton(root, text="Change Version", command=show_version_popup, font=("Arial", 16))
    change_version_button.place(relx=0.7, rely=0.57, anchor="center")

    install_button = ctk.CTkButton(root, text="Install", command=install_version, font=("Arial", 20, "bold"), height=50)
    install_button.place(relx=0.7, rely=0.70, anchor="center")

    check_installed()
    root.mainloop()

if __name__ == "__main__":
    main()
