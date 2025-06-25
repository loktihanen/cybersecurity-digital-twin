# ======================== IMPORTS ========================
import os
from urllib.parse import quote_plus
from py2neo import Graph
from rdflib import Graph as RDFGraph, Namespace, OWL, URIRef

# ======================== CONFIG NEO4J ========================
uri = os.getenv("NEO4J_URI", "neo4j+s://8d5fbce8.databases.neo4j.io")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM")
graph = Graph(uri, auth=(user, password))

# ======================== 1. FUSION LOGIQUE CVE ========================
print("🔄 Lancement de la fusion logique entre CVE KG1 (NVD) et KG2 (Nessus)...")

fusion_query = """
MATCH (c1:CVE)-[:SAME_AS]-(c2:CVE)
WHERE c1.source = 'NVD' AND c2.source = 'NESSUS'

MERGE (u:CVE_UNIFIED {name: c1.name})
SET u.cvss         = coalesce(c1.cvss_score, c2.cvss_score),
    u.severity     = coalesce(c1.severity, c2.severity),
    u.attackVector = coalesce(c1.attackVector, c2.attackVector),
    u.description  = coalesce(c1.description, c2.description)

WITH c1, c2, u
CALL {
  WITH c1, u
  MATCH (c1)-[r]->(x)
  WHERE type(r) <> 'SAME_AS'
  CALL apoc.create.relationship(u, type(r), properties(r), x) YIELD rel
  RETURN count(*) AS out1
}
CALL {
  WITH c2, u
  MATCH (c2)-[r]->(x)
  WHERE type(r) <> 'SAME_AS'
  CALL apoc.create.relationship(u, type(r), properties(r), x) YIELD rel
  RETURN count(*) AS out2
}
CALL {
  WITH c1, u
  MATCH (x)-[r]->(c1)
  WHERE type(r) <> 'SAME_AS'
  CALL apoc.create.relationship(x, type(r), properties(r), u) YIELD rel
  RETURN count(*) AS in1
}
CALL {
  WITH c2, u
  MATCH (x)-[r]->(c2)
  WHERE type(r) <> 'SAME_AS'
  CALL apoc.create.relationship(x, type(r), properties(r), u) YIELD rel
  RETURN count(*) AS in2
}
RETURN count(DISTINCT u) AS cves_unifiees
"""
result = graph.run(fusion_query).data()
nb_unifies = result[0]['cves_unifiees'] if result else 0

# ======================== 1 BIS. TOTAL FUSIONS ========================
total_query = """
MATCH (c:CVE)-[:SAME_AS]-(n:CVE)
WHERE c.source = 'NVD' AND n.source = 'NESSUS'
RETURN count(DISTINCT c) AS total_fusionnees
"""
total = graph.run(total_query).data()
total_fusionnees = total[0]['total_fusionnees'] if total else 0

print(f"✅ {nb_unifies} CVE fusionnées dans cette exécution.")
print(f"📊 Total global des CVE fusionnées : {total_fusionnees}")

# ======================== 2. INITIALISATION RDF ========================
kg = RDFGraph()
CYBER = Namespace("http://example.org/cyber#")
UNIFIED = Namespace("http://example.org/unified#")

kg.bind("cyber", CYBER)
kg.bind("unified", UNIFIED)
kg.bind("owl", OWL)

def iri_fragment(txt: str) -> str:
    return quote_plus(txt.strip().replace("/", "_"))

# ======================== 3. owl:sameAs entre CVE NVD ↔ Nessus ========================
query_same_as = """
MATCH (c1:CVE)-[:SAME_AS]-(c2:CVE)
WHERE c1.source = 'NVD' AND c2.source = 'NESSUS'
RETURN DISTINCT c1.name AS cve1, c2.name AS cve2
"""
rows = graph.run(query_same_as).data()
count_same_as = 0

for row in rows:
    cve1 = row["cve1"]
    cve2 = row["cve2"]
    if not cve1 or not cve2:
        continue
    uri1 = CYBER[f"CVE/{iri_fragment(cve1)}"]
    uri2 = CYBER[f"CVE/{iri_fragment(cve2)}"]
    kg.add((URIRef(uri1), OWL.sameAs, URIRef(uri2)))
    count_same_as += 1

print(f"🔁 {count_same_as} owl:sameAs ajoutés entre CVE NVD et Nessus.")

# ======================== 4. owl:sameAs vers CVE_UNIFIED ========================
query_unified = """
MATCH (u:CVE_UNIFIED)
RETURN u.name AS name
"""
rows_unified = graph.run(query_unified).data()
count_align = 0

for row in rows_unified:
    name = row["name"]
    if not name:
        continue
    uri_cve = CYBER[f"CVE/{iri_fragment(name)}"]
    uri_unified = UNIFIED[f"{iri_fragment(name)}"]
    kg.add((URIRef(uri_cve), OWL.sameAs, URIRef(uri_unified)))
    count_align += 1

print(f"🔗 {count_align} owl:sameAs ajoutés vers les nœuds CVE_UNIFIED.")

# ======================== 5. EXPORT FINAL ========================
output_file = "exports/kg_fusionne.ttl"
os.makedirs(os.path.dirname(output_file), exist_ok=True)
kg.serialize(destination=output_file, format="turtle")

print(f"📄 Fichier RDF exporté : {output_file}")
print(f"📌 Total owl:sameAs : {count_same_as + count_align}")

