# ======================== 1. INSTALLATION ========================
!pip install py2neo pandas rdflib python-Levenshtein

# ======================== 2. IMPORTS ============================
import pandas as pd
from py2neo import Graph, Node, Relationship, NodeMatcher
from rdflib import Graph as RDFGraph, Namespace, RDF, RDFS, OWL, Literal
from urllib.parse import quote_plus
from datetime import datetime
from google.colab import files

# ---------- utilitaire IRI ----------
def iri_fragment(txt: str) -> str:
    return quote_plus(txt.strip().replace("/", "_"))

# ======================== 3. UPLOAD CSV =========================
uploaded = files.upload()
csv_path = list(uploaded.keys())[0]

# ======================== 4. CONNEXION NEO4J =====================
uri  = "neo4j+s://8d5fbce8.databases.neo4j.io"
user = "neo4j"
pwd  = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph   = Graph(uri, auth=(user, pwd))
matcher  = NodeMatcher(graph)

# ======================== 5. ONTOLOGIE STUCO =====================
kg    = RDFGraph()
STUCO = Namespace("http://w3id.org/sepses/vocab/ref/stuco#")
CYBER = Namespace("http://example.org/cyber#")
kg.bind("stuco", STUCO)
kg.bind("cyber", CYBER)

# Classes principales
for lbl, uri_cls in [
    ("Host", CYBER.Host),
    ("Plugin", CYBER.Plugin),
    ("Service", CYBER.Service),
    ("CVE", STUCO.Vulnerability),
    ("Source", CYBER.Source)  # ajout classe Source
]:
    kg.add((uri_cls, RDF.type, OWL.Class))
    kg.add((uri_cls, RDFS.label, Literal(lbl)))

# Propriétés objet
for lbl, prop in [
    ("hasPlugin", CYBER.hasPlugin),
    ("detects", CYBER.detects),
    ("runsService", CYBER.runsService),
    ("isVulnerableTo", CYBER.isVulnerableTo),
    ("comesFrom", CYBER.comesFrom)  # ajout propriété comesFrom
]:
    kg.add((prop, RDF.type, OWL.ObjectProperty))
    kg.add((prop, RDFS.label, Literal(lbl)))

# Instances des sources
kg.add((CYBER["NVD"], RDF.type, CYBER.Source))
kg.add((CYBER["NVD"], RDFS.label, Literal("NVD")))
kg.add((CYBER["NESSUS"], RDF.type, CYBER.Source))
kg.add((CYBER["NESSUS"], RDFS.label, Literal("NESSUS")))

# ======================== 6. LECTURE + NORMALISATION CSV =========
df = pd.read_csv(csv_path)

# a) uniforme : trim, lower, espace→_
df.columns = (df.columns.str.strip()
                        .str.lower()
                        .str.replace(" ", "_"))

# b) alias fréquents → nom canonique
alias = {
    "pluginid":        "plugin_id",
    "plugin_id_":      "plugin_id",
    "id":              "plugin_id",
    "plugin_name":     "plugin_name",
    "name":            "plugin_name",
    "risk_factor":     "risk",
}
df = df.rename(columns=alias)

required = {"host", "plugin_name", "plugin_id", "port"}
missing  = required - set(df.columns)
if missing:
    raise ValueError(f"🚨 Colonnes manquantes dans le CSV : {missing}")

# ======================== 7. INSERTION NEO4J + RDF ===============
now_iso = datetime.utcnow().isoformat()

for _, r in df.iterrows():
    host_ip   = str(r["host"]).strip()
    plug_id   = str(r["plugin_id"]).strip()
    plug_name = str(r["plugin_name"]).strip()
    port      = str(r["port"]).strip()
    service   = str(r.get("service", "unknown")).strip()
    cves      = [c.strip() for c in str(r.get("cve", "")).split(",") if c.startswith("CVE")]

    tx = graph.begin()

    n_host = Node("Host", name=host_ip, last_seen=now_iso)
    tx.merge(n_host, "Host", "name")

    n_plugin = Node("Plugin", plugin_id=plug_id, plugin_name=plug_name)
    tx.merge(n_plugin, "Plugin", "plugin_id")
    tx.merge(Relationship(n_host, "HAS_PLUGIN", n_plugin))

    if port and port != "nan":
        n_port = Node("Port", port=port)
        tx.merge(n_port, "Port", "port")
        tx.merge(Relationship(n_host, "CONNECTED_TO", n_port))

    if service:
        n_serv = Node("Service", name=service)
        tx.merge(n_serv, "Service", "name")
        tx.merge(Relationship(n_host, "RUNS_SERVICE", n_serv))

    # CVE
    for cve in cves:
        n_cve = matcher.match("CVE", name=cve).first() or Node("CVE", name=cve, source="NESSUS")
        tx.merge(n_cve, "CVE", "name")
        tx.merge(Relationship(n_plugin, "DETECTS", n_cve))
        tx.merge(Relationship(n_host, "IS_VULNERABLE_TO", n_cve))

        # RDF liens
        resCVE = CYBER[f"CVE/{iri_fragment(cve)}"]
        kg.add((CYBER[f"Plugin/{iri_fragment(plug_id)}"], CYBER.detects, resCVE))
        kg.add((CYBER[f"Host/{iri_fragment(host_ip)}"], CYBER.isVulnerableTo, resCVE))
        kg.add((resCVE, CYBER.comesFrom, CYBER["NESSUS"]))   # provenance explicite

    tx.commit()

    # RDF de base (hors boucle CVE)
    resH = CYBER[f"Host/{iri_fragment(host_ip)}"]
    resP = CYBER[f"Plugin/{iri_fragment(plug_id)}"]
    kg.add((resH, CYBER.hasPlugin, resP))
    if service:
        kg.add((resH, CYBER.runsService, CYBER[f"Service/{iri_fragment(service)}"]))

# ======================== 8. EXPORT RDF ==========================
kg.serialize("kg2.ttl", format="turtle")
print("✅ kg2.ttl généré (ontologie STUCO) et Neo4j mis à jour.")

# ======================== 9. Post-traitement source NESSUS en Neo4j =
graph.run("""
MATCH (c:CVE)<-[:DETECTS]-(:Plugin)<-[:HAS_PLUGIN]-(:Host)
WHERE c.source IS NULL OR c.source <> 'NVD'
SET c.source = 'NESSUS'
""")
