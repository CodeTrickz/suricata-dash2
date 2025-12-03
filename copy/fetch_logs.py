#!/usr/bin/env python3
import os
import shutil
import stat
import subprocess
import time

# ================== CONFIG ==================
PFSENSE_HOST = "192.168.10.1"              # pfSense IP
PFSENSE_USER = "admin"                     # pfSense login user
REMOTE_DIR = "/var/log/suricata"  # Suricata-logmap op pfSense (alle subdirectories)
LOCAL_DIR = "./copy/"                      # Definitieve map
TEMP_DIR = "./temp_suricata/"              # Tijdelijke map waar eerst alles in komt
INTERVAL_SECONDS = 30                      # Hoe vaak opnieuw ophalen
SSH_TIMEOUT = 10                           # Timeout voor SSH commando's (seconden)
SCP_TIMEOUT = 120                         # Timeout voor SCP downloads (seconden) - verhoogd voor grote bestanden
SCP_RETRIES = 1                            # Aantal retries bij timeout/fout
# ============================================


def ensure_dir(path):
    if not os.path.exists(path):
        print(f"[*] Directory {path} bestaat nog niet, aanmaken...")
        os.makedirs(path, exist_ok=True)


def safe_remove(path):
    def _handle_error(func, target, exc_info):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except Exception as err:  # pragma: no cover
            print(f"[!] Kon {target} niet verwijderen: {err}")

    if os.path.isdir(path):
        shutil.rmtree(path, onerror=_handle_error)
    else:
        os.remove(path)


def run_with_timeout(cmd, timeout_seconds, description=""):
    """
    Voert een commando uit met timeout.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
        return result
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout ({timeout_seconds}s) bij {description}")
        return None
    except Exception as e:
        print(f"[!] Fout bij {description}: {e}")
        return None


def get_remote_directories():
    """
    Haalt de lijst van suricata directories op van de remote server.
    """
    # SSH commando om directories op te halen die beginnen met suricata_
    cmd = [
        "ssh",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        f"{PFSENSE_USER}@{PFSENSE_HOST}",
        f"ls -1 {REMOTE_DIR} 2>/dev/null | grep '^suricata_' || true"
    ]
    
    result = run_with_timeout(cmd, SSH_TIMEOUT, "ophalen directory lijst")
    
    if result is None:
        return []
    
    if result.returncode != 0:
        if result.stderr:
            print(f"[!] Fout bij ophalen directory lijst: {result.stderr.strip()}")
        return []
    
    dirs = [d.strip() for d in result.stdout.strip().split('\n') if d.strip()]
    return sorted(dirs)


def get_files_in_directory(remote_dir_path):
    """
    Haalt de lijst van bestanden op in een remote directory (zonder eve.json).
    """
    cmd = [
        "ssh",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        f"{PFSENSE_USER}@{PFSENSE_HOST}",
        f"ls -1 {remote_dir_path} 2>/dev/null | grep -v '^eve.json$' || true"
    ]
    
    result = run_with_timeout(cmd, SSH_TIMEOUT, f"ophalen bestandslijst uit {remote_dir_path}")
    
    if result is None or result.returncode != 0:
        return []
    
    files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
    return files


def fetch_to_temp():
    """
    Haalt Suricata logs één voor één binnen naar de tijdelijke map.
    """
    ensure_dir(TEMP_DIR)

    # Maak TEMP_DIR leeg zodat oude rommel weg is
    for f in os.listdir(TEMP_DIR):
        path = os.path.join(TEMP_DIR, f)
        safe_remove(path)

    # Haal lijst van directories op
    remote_dirs = get_remote_directories()
    
    if not remote_dirs:
        print("[!] Geen suricata directories gevonden op remote server.")
        return False

    print(f"[+] Gevonden {len(remote_dirs)} directories: {', '.join(remote_dirs)}")
    print(f"[+] Download naar tijdelijke map: {TEMP_DIR}")

    success_count = 0
    for dirname in remote_dirs:
        remote_dir_path = f"{REMOTE_DIR}/{dirname}"
        local_path = os.path.join(TEMP_DIR, dirname)
        ensure_dir(local_path)
        
        print(f"    [*] Downloaden {dirname} (eve.json wordt overgeslagen)...")
        
        # Haal lijst van bestanden op (zonder eve.json)
        files = get_files_in_directory(remote_dir_path)
        
        if not files:
            print(f"    [!] Geen bestanden gevonden in {dirname} (of alleen eve.json)")
            continue
        
        file_count = 0
        total_files = len(files)
        for idx, filename in enumerate(files, 1):
            remote_file_path = f"{PFSENSE_USER}@{PFSENSE_HOST}:{remote_dir_path}/{filename}"
            local_file_path = os.path.join(local_path, filename)
            
            print(f"      [{idx}/{total_files}] Downloaden {filename}...", end=" ", flush=True)
            
            cmd = [
                "scp",
                "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=3",
                "-q",  # Quiet mode voor minder output
                remote_file_path,
                local_file_path
            ]
            
            # Retry mechanisme voor grote bestanden
            downloaded = False
            for attempt in range(SCP_RETRIES + 1):
                if attempt > 0:
                    print(f"\n        Retry {attempt}/{SCP_RETRIES}...", end=" ", flush=True)
                
                result = run_with_timeout(cmd, SCP_TIMEOUT, f"downloaden {filename}")
                
                if result is None:
                    if attempt < SCP_RETRIES:
                        continue  # Probeer opnieuw
                    else:
                        print("TIMEOUT (na retries)")
                        break
                
                if result.returncode == 0:
                    # Controleer of bestand daadwerkelijk is gedownload
                    if os.path.exists(local_file_path) and os.path.getsize(local_file_path) > 0:
                        file_count += 1
                        file_size = os.path.getsize(local_file_path)
                        size_mb = file_size / (1024 * 1024)
                        print(f"OK ({size_mb:.2f} MB)")
                        downloaded = True
                        break
                    else:
                        if attempt < SCP_RETRIES:
                            continue  # Bestand is leeg, probeer opnieuw
                        else:
                            print("FOUT: Bestand is leeg")
                            break
                else:
                    error_msg = result.stderr.strip() if result.stderr else "onbekende fout"
                    if attempt < SCP_RETRIES:
                        print(f"FOUT, retry...", end=" ", flush=True)
                        time.sleep(1)  # Korte pauze voor retry
                        continue
                    else:
                        print(f"FOUT: {error_msg[:50]}")
                        break
            
            if not downloaded:
                # Verwijder mogelijk corrupte/lege bestand
                if os.path.exists(local_file_path):
                    try:
                        os.remove(local_file_path)
                    except:
                        pass
        
        if file_count > 0:
            print(f"    [+] {dirname} gedownload: {file_count}/{len(files)} bestanden (eve.json overgeslagen).")
            success_count += 1
        else:
            print(f"    [!] Geen bestanden gedownload uit {dirname}")

    print(f"[+] Download voltooid: {success_count}/{len(remote_dirs)} directories succesvol (eve.json niet gedownload).")
    return success_count > 0


def copy_temp_to_final():
    """
    Kopieert ALLES uit de temp map naar de echte local_dir nadat download klaar is.
    """
    ensure_dir(LOCAL_DIR)

    print(f"[+] Kopieer ALLE inhoud van temp naar {LOCAL_DIR} ...")

    try:
        copied_items = []
        # Kopieer alles recursief (niet de temp-map zelf)
        for item in os.listdir(TEMP_DIR):
            src = os.path.join(TEMP_DIR, item)
            dest = os.path.join(LOCAL_DIR, item)

            # Als het een map is → volledig recursief kopiëren
            if os.path.isdir(src):
                if os.path.exists(dest):
                    # Als destination bestaat, verwijder eerst en kopieer opnieuw voor volledige sync
                    shutil.rmtree(dest, ignore_errors=True)
                shutil.copytree(src, dest, dirs_exist_ok=True)
                copied_items.append(f"directory {item}")
            else:
                # Bestand kopiëren
                shutil.copy2(src, dest)
                copied_items.append(f"bestand {item}")

        if copied_items:
            print(f"[+] Kopiëren naar {LOCAL_DIR} gelukt: {len(copied_items)} items gekopieerd.")
            print(f"    Items: {', '.join(copied_items[:5])}{'...' if len(copied_items) > 5 else ''}\n")
        else:
            print(f"[!] Geen items gevonden in {TEMP_DIR} om te kopiëren.\n")
    except Exception as e:
        print(f"[!] Kopie-fout: {e}\n")


def main():
    print("[*] Suricata log fetcher gestart.")
    print(f"    pfSense: {PFSENSE_USER}@{PFSENSE_HOST}")
    print(f"    Remote : {REMOTE_DIR}")
    print(f"    Temp   : {TEMP_DIR}")
    print(f"    Final  : {LOCAL_DIR}")
    print(f"    Interval: {INTERVAL_SECONDS} sec")
    print(f"    Modus  : Verwerkt directories één voor één\n")

    while True:
        if fetch_to_temp():
            copy_temp_to_final()
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
