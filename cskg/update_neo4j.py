import os
import time
import requests
from datetime import datetime
from py2neo import Graph, Node, Relationship
from transformers import pipeline

# ======================== CONFIGURATION ========================
uri = os.getenv("NEO4J_URI", "neo4j+s://8d5fbce8.databases.neo4j.io")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM")
graph = Graph(uri, auth=(user, password))

NER_MODEL = "dslim/bert-base-NER"
NER_THRESHOLD = 0.5

# ======================== INIT PIPELINE NER ========================
print("📦 Chargement du modèle NER...")
ner_pipeline = pipeline("ner", model=NER_MODEL, aggregation_strategy="simple")

# ======================== API NVD ========================
def fetch_cve_nvd(start=0, results_per_page=50):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"❌ Erreur API NVD : {response.status_code}")
        return None
    return response.json()

# ======================== INSERTION NEO4J ========================
def insert_cve(item):
    cve_id = item["cve"]["id"]
    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")

    if graph.nodes.match("CVE", name=cve_id).first():
        print(f"↪️ {cve_id} déjà présent. Ignoré.")
        return

    node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published:
        node["published"] = published

    # CVSS
    try:
        metrics = item["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            node["cvss_score"] = data.get("baseScore")
            node["severity"] = data.get("baseSeverity")
            node["attackVector"] = data.get("attackVector")
            node["privilegesRequired"] = data.get("privilegesRequired")
            node["userInteraction"] = data.get("userInteraction")
            node["vectorString"] = data.get("vectorString")
    except Exception as e:
        print(f"⚠️ CVSS erreur {cve_id} : {e}")

    graph.create(node)

    # CWE
    for weakness in item["cve"].get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc["value"]
            if "CWE" in cwe_id:
                cwe_node = graph.nodes.match("CWE", name=cwe_id).first()
                if not cwe_node:
                    cwe_node = Node("CWE", name=cwe_id)
                    graph.create(cwe_node)
                graph.create(Relationship(node, "CLASSIFIED_AS", cwe_node))

    # CPE
    try:
        nodes = item["cve"]["configurations"][0]["nodes"]
        for config in nodes:
            for cpe in config.get("cpeMatch", []):
                cpe_uri = cpe["criteria"]
                cpe_node = Node("CPE", name=cpe_uri)
                graph.merge(cpe_node, "CPE", "name")
                graph.create(Relationship(node, "AFFECTS", cpe_node))
    except:
        pass

    # NER
    try:
        entities = ner_pipeline(description)
        for ent in entities:
            if ent["score"] < NER_THRESHOLD:
                continue
            word = ent["word"]
            ent_type = ent["entity_group"]
            ent_node = Node("Entity", name=word, type=ent_type)
            graph.merge(ent_node, "Entity", "name")
            graph.create(Relationship(node, "MENTIONS", ent_node))
    except Exception as e:
        print(f"⚠️ NER erreur {cve_id} : {e}")

# ======================== PIPELINE DE MISE À JOUR ========================
def update_graph_cve(max_pages=1, per_page=50):
    print(f"🚀 Démarrage de la mise à jour NVD (pages: {max_pages})")
    for page in range(max_pages):
        data = fetch_cve_nvd(start=page * per_page, results_per_page=per_page)
        if not data:
            break
        vulns = data.get("vulnerabilities", [])
        print(f"📦 {len(vulns)} vulnérabilités reçues - page {page + 1}")
        for item in vulns:
            try:
                insert_cve(item)
                time.sleep(0.2)
            except Exception as e:
                print(f"[!] Erreur insertion CVE : {e}")
    print("✅ Mise à jour NVD terminée.")

# ======================== MAIN ========================
if __name__ == "__main__":
    update_graph_cve(max_pages=2, per_page=50)  # configurable

