# ======================== INSTALLATION ========================
!pip install py2neo rdflib --quiet

# ======================== IMPORTATIONS ========================
from py2neo import Graph
from rdflib import Graph as RDFGraph, Namespace, OWL, URIRef
from urllib.parse import quote_plus

# ======================== CONNEXION NEO4J ========================
uri      = "neo4j+s://8d5fbce8.databases.neo4j.io"
user     = "neo4j"
password = "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM"
graph    = Graph(uri, auth=(user, password))

# ======================== 1. FUSION LOGIQUE DES CVE ========================
fusion_query = """
MATCH (c1:CVE)-[:SAME_AS]-(c2:CVE)
WHERE c1.source = 'NVD' AND c2.source = 'NESSUS'

MERGE (u:CVE_UNIFIED {name: c1.name})
SET u.cvss         = coalesce(c1.cvss, c2.cvss),
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

# ======================== 1 bis. TOTAL FUSIONS ========================
query_total = """
MATCH (c:CVE)-[:SAME_AS]-(n:CVE)
WHERE c.source = 'NVD' AND n.source = 'NESSUS'
RETURN count(DISTINCT c) AS total_fusionnees
"""
total = graph.run(query_total).data()
total_fusionnees = total[0]["total_fusionnees"] if total else 0

print(f"✅ Nombre de CVE fusionnées dans cette exécution : {nb_unifies}")
print(f"📊 Nombre total de CVE déjà fusionnées dans la base : {total_fusionnees}")

# ======================== 2. INITIALISATION GRAPHE RDF ========================
kg      = RDFGraph()
CYBER   = Namespace("http://example.org/cyber#")
UNIFIED = Namespace("http://example.org/unified#")

kg.bind("cyber", CYBER)
kg.bind("unified", UNIFIED)
kg.bind("owl", OWL)

def iri_fragment(txt: str) -> str:
    return quote_plus(txt.strip().replace("/", "_"))

# ======================== 3. owl:sameAs entre CVE NVD et Nessus ========================
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
    if isinstance(cve1, list): cve1 = cve1[0] if cve1 else ""
    if isinstance(cve2, list): cve2 = cve2[0] if cve2 else ""
    if not cve1 or not cve2: continue

    uri1 = CYBER[f"CVE/{iri_fragment(cve1)}"]
    uri2 = CYBER[f"CVE/{iri_fragment(cve2)}"]
    kg.add((URIRef(uri1), OWL.sameAs, URIRef(uri2)))
    count_same_as += 1

print(f"🔁 owl:sameAs entre CVE NVD et Nessus : {count_same_as}")

# ======================== 3 bis. owl:sameAs vers CVE_UNIFIED ========================
query_unified = """
MATCH (u:CVE_UNIFIED)
RETURN u.name AS name
"""
unified_nodes = graph.run(query_unified).data()

count_align = 0
for row in unified_nodes:
    name = row["name"]
    if not name: continue

    uri_cve      = CYBER[f"CVE/{iri_fragment(name)}"]
    uri_unified  = UNIFIED[f"{iri_fragment(name)}"]
    kg.add((URIRef(uri_cve), OWL.sameAs, URIRef(uri_unified)))
    count_align += 1

print(f"🔗 Alignements RDF vers CVE_UNIFIED : {count_align}")

# ======================== 4. EXPORT RDF FINAL ========================
kg.serialize("kg_fusionne.ttl", format="turtle")
print("📄 Fichier RDF enrichi généré : kg_fusionne.ttl")
print(f"🔢 Nombre de relations owl:sameAs ajoutées : {count_same_as + count_align}")
