# === Ajouter au début
import argparse, json

parser = argparse.ArgumentParser()
parser.add_argument("--file", help="Fichier JSON contenant les CVEs à injecter")
args = parser.parse_args()

# ======================== 0. IMPORTS ========================
from py2neo import Graph, Node, Relationship
from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
import requests
import time
from datetime import datetime

# ======================== 1. CONNEXION NEO4J ========================
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))

# ======================== 2. RDF ONTOLOGY INITIALIZATION ========================
rdf_graph = RDFGraph()
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco#")
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")

rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

# RDF Classes declaration
for label, uri_ in [
    ("CVE", STUCO.Vulnerability),
    ("CWE", STUCO.Weakness),
    ("CPE", STUCO.Platform),
    ("Entity", CYBER.Entity)
]:
    rdf_graph.add((uri_, RDF.type, OWL.Class))
    rdf_graph.add((uri_, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="kg1.ttl", format="turtle")

# ======================== 3. NER WITH BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 4. FETCH DATA FROM NVD ========================
def fetch_cve_nvd(start=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    return response.json()

# ======================== 5. INSERTION LOGIC ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")

    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published:
        cve_node["published"] = published

    # --- CVSS Base Score ---
    try:
        metrics = item["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            cve_node["cvss_score"] = data.get("baseScore")
            cve_node["severity"] = data.get("baseSeverity")
            cve_node["attackVector"] = data.get("attackVector")
            cve_node["privilegesRequired"] = data.get("privilegesRequired")
            cve_node["userInteraction"] = data.get("userInteraction")
            cve_node["vectorString"] = data.get("vectorString")
    except Exception as e:
        print(f"⚠️ Problème CVSS sur {cve_id} : {e}")

    graph.merge(cve_node, "CVE", "name")

    # --- CWE ---
    for weakness in item["cve"].get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc["value"]
            if "CWE" in cwe_id:
                existing = graph.nodes.match("CWE", name=cwe_id).first()
                cwe_node = existing if existing else Node("CWE", name=cwe_id)
                graph.merge(cwe_node, "CWE", "name")
                graph.merge(Relationship(cve_node, "ASSOCIATED_WITH", cwe_node))

    # --- CPE ---
    try:
        nodes = item["cve"]["configurations"][0]["nodes"]
        for config in nodes:
            for cpe in config.get("cpeMatch", []):
                cpe_uri = cpe["criteria"]
                cpe_node = Node("CPE", name=cpe_uri)
                graph.merge(cpe_node, "CPE", "name")
                graph.merge(Relationship(cve_node, "AFFECTS", cpe_node))
    except:
        pass

    # --- NER sur description ---
    try:
        entities = ner(description)
        for ent in entities:
            word = ent["word"]
            ent_type = ent["entity_group"]
            ent_node = Node("Entity", name=word, type=ent_type)
            graph.merge(ent_node, "Entity", "name")
            graph.merge(Relationship(cve_node, "MENTIONS", ent_node))
    except Exception as e:
        print(f"⚠️ NER erreur sur {cve_id}: {e}")

# ======================== 6. PIPELINE EXECUTION ========================
def pipeline_kg1(start=0, results_per_page=10):
    print("🚀 Extraction des CVEs depuis NVD...")
    data = fetch_cve_nvd(start=start, results_per_page=results_per_page)
    for item in data.get("vulnerabilities", []):
        try:
            insert_cve_neo4j(item)
            time.sleep(0.2)
        except Exception as e:
            print(f"[!] Erreur pour {item['cve']['id']}: {e}")
    print("✅ Insertion terminée dans Neo4j.")

# ======================== 7. MAIN ========================
if __name__ == "__main__":
    if args.file:
        with open(args.file, "r") as f:
            data = json.load(f)
        for item in data.get("vulnerabilities", []):
            try:
                insert_cve_neo4j(item)
            except Exception as e:
                print(f"[!] Erreur pour {item['cve']['id']}: {e}")
    else:
        pipeline_kg1(start=0, results_per_page=20)

