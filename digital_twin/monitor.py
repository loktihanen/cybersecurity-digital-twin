# ======================== MONITORING CVE (NVD) ========================
import requests
import time
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import schedule

# === CONFIGURATION ===
LAST_CHECK_FILE = Path("digital_twin/last_check.txt")
CHECK_INTERVAL_MINUTES = 60  # à modifier si besoin

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# === FONCTION : heure du dernier check
def get_last_check_time():
    if LAST_CHECK_FILE.exists():
        with open(LAST_CHECK_FILE, "r") as f:
            return datetime.fromisoformat(f.read().strip())
    return datetime.utcnow() - timedelta(days=1)

# === FONCTION : mise à jour heure du dernier check
def update_last_check_time():
    with open(LAST_CHECK_FILE, "w") as f:
        f.write(datetime.utcnow().isoformat())

# === FONCTION : appel API NVD
def fetch_new_cves(published_after):
    print(f"🔎 Vérification des CVEs publiées après : {published_after}")
    params = {
        "pubStartDate": published_after.isoformat() + "Z",
        "resultsPerPage": 100
    }
    response = requests.get(NVD_API_URL, params=params)
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])

# === PIPELINE : si nouvelle CVE trouvée
def run_monitoring():
    print(f"🕒 Lancement du monitoring : {datetime.utcnow().isoformat()}")

    last_check = get_last_check_time()
    new_cves = fetch_new_cves(last_check)

    if not new_cves:
        print("✅ Aucune nouvelle CVE détectée.")
    else:
        print(f"🚨 {len(new_cves)} nouvelle(s) CVE trouvée(s).")

        # 1. Stocker temporairement
        tmp_file = Path("digital_twin/tmp_new_cves.json")
        with open(tmp_file, "w") as f:
            json.dump({"vulnerabilities": new_cves}, f)

        # 2. Exécuter collect_nvd.py
        subprocess.run(["python", "cskg/collect_nvd.py", "--file", str(tmp_file)], check=True)

        # 3. Exécuter update_neo4j.py
        subprocess.run(["python", "cskg/update_neo4j.py"], check=True)

        # 4. Nettoyer
        tmp_file.unlink()

    update_last_check_time()
    print("⏱️ Monitoring terminé.")

# === PLANNING AVEC SCHEDULE (pour Windows)
schedule.every(CHECK_INTERVAL_MINUTES).minutes.do(run_monitoring)

if __name__ == "__main__":
    print("🚀 Monitor actif — toutes les", CHECK_INTERVAL_MINUTES, "minutes.")
    run_monitoring()  # première exécution immédiate

    while True:
        schedule.run_pending()
        time.sleep(10)

