# ======================== 1. IMPORTS ========================
!pip install py2neo
from py2neo import Graph, Node, Relationship
from transformers import pipeline
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
import requests
import time
from datetime import datetime, timedelta

# ======================== 2. CONNEXION NEO4J ========================
uri = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph = Graph(uri, auth=(user, password))

# ======================== 3. ONTOLOGIE RDF UCO/STUCO ========================
rdf_graph = RDFGraph()
UCO = Namespace("https://ontology.unifiedcyberontology.org/uco#")
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")

rdf_graph.bind("uco", UCO)
rdf_graph.bind("stuco", STUCO)
rdf_graph.bind("cyber", CYBER)

classes = [
    ("CVE", STUCO.Vulnerability), ("CWE", STUCO.Weakness), ("CPE", STUCO.Platform),
    ("Entity", CYBER.Entity)
]
for label, uri in classes:
    rdf_graph.add((uri, RDF.type, OWL.Class))
    rdf_graph.add((uri, RDFS.label, Literal(label)))

rdf_graph.serialize(destination="kg1.ttl", format="turtle")

# ======================== 4. NER AVEC BERT ========================
ner = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")

# ======================== 5. API NVD ========================
def fetch_cve_nvd(start=0, results_per_page=20):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    return response.json()

# ======================== 6. INSERTION DANS NEO4J ========================
def insert_cve_neo4j(item):
    cve_id = item["cve"]["id"]
    description = item["cve"]["descriptions"][0]["value"]
    published = item["cve"].get("published")

    # 🔧 Création noeud CVE
    cve_node = Node("CVE", name=cve_id, description=description, source="NVD")
    if published:
        cve_node["published"] = published

    # 🔐 CVSS
    try:
        metrics = item["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            cve_node["cvss_score"] = data["baseScore"]
            cve_node["severity"] = data["baseSeverity"]
    except:
        pass

    graph.merge(cve_node, "CVE", "name")

    # 🔁 CWE
    # 🔁 CWE avec contrôle unicité
    for weakness in item["cve"].get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_id = desc["value"]
            if "CWE" in cwe_id:
                existing = graph.nodes.match("CWE", name=cwe_id).first()
                if existing:
                    cwe_node = existing
                else:
                    cwe_node = Node("CWE", name=cwe_id)
                    graph.create(cwe_node)
                graph.merge(Relationship(cve_node, "ASSOCIATED_WITH", cwe_node))


    # 🔁 CPE
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
    # 🔐 CVSS - enrichissement vectoriel
    try:
         metrics = item["cve"]["metrics"]
         if "cvssMetricV31" in metrics:
             data = metrics["cvssMetricV31"][0]["cvssData"]
             cve_node["cvss_score"] = data["baseScore"]
             cve_node["severity"] = data["baseSeverity"]
             cve_node["attackVector"] = data.get("attackVector")
             cve_node["privilegesRequired"] = data.get("privilegesRequired")
             cve_node["userInteraction"] = data.get("userInteraction")
             cve_node["vectorString"] = data.get("vectorString")
    except Exception as e:
        print(f"⚠️ Problème CVSS sur {cve_id} : {e}")

    # 🔎 NER sur la description
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

# ======================== 7. PIPELINE ========================
def pipeline_kg1(start=0, results_per_page=10):
    print("🚀 Début de l’extraction depuis NVD...")
    data = fetch_cve_nvd(start=start, results_per_page=results_per_page)
    for item in data.get("vulnerabilities", []):
        try:
            insert_cve_neo4j(item)
            time.sleep(0.2)
        except Exception as e:
            print(f"[!] Erreur pour {item['cve']['id']}: {e}")
    print("✅ Données insérées dans Neo4j.")

# ======================== 8. EXECUTION ========================
pipeline_kg1(start=0, results_per_page=20)
