# ======================== IMPORTS ========================
import os
import numpy as np
import csv
from tqdm import tqdm
from py2neo import Graph, NodeMatcher, Relationship
from fuzzywuzzy import fuzz
from sentence_transformers import SentenceTransformer

# ======================== CONFIG NEO4J ========================
uri = os.getenv("NEO4J_URI", "neo4j+s://8d5fbce8.databases.neo4j.io")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM")
graph = Graph(uri, auth=(user, password))
matcher = NodeMatcher(graph)

# ======================== CORRECTION SOURCE NESSUS ========================
graph.run("""
MATCH (c:CVE)<-[:DETECTS]-(:Plugin)<-[:HAS_PLUGIN]-(:Host)
WHERE c.source IS NULL OR c.source <> 'NVD'
SET c.source = 'NESSUS'
""")

# ======================== CHARGEMENT DES CVEs ========================
print("🔍 Chargement des CVE KG1 (NVD)...")
kg1_cves = list(matcher.match("CVE").where("_.source = 'NVD'"))

print("🔍 Chargement des CVE KG2 (NESSUS)...")
kg2_cves = list(matcher.match("CVE").where("_.source = 'NESSUS'"))

print(f"📦 KG1 (NVD): {len(kg1_cves)} CVEs | KG2 (Nessus): {len(kg2_cves)} CVEs")

def normalize_cve(name):
    return name.strip().upper()

kg1_map = {normalize_cve(n["name"]): n for n in kg1_cves}
kg2_map = {normalize_cve(n["name"]): n for n in kg2_cves}
kg1_names = list(kg1_map.keys())
kg2_names = list(kg2_map.keys())

# ======================== EMBEDDINGS ========================
print("⚙️ Chargement modèle SentenceTransformer...")
model = SentenceTransformer("all-mpnet-base-v2")

def get_cve_text(node):
    return f"{node['name']} {node.get('description', '')}"

print("⚙️ Encodage KG1...")
kg1_texts = [get_cve_text(kg1_map[name]) for name in kg1_names]
kg1_emb = model.encode(kg1_texts, convert_to_numpy=True, show_progress_bar=True)

print("⚙️ Encodage KG2...")
kg2_texts = [get_cve_text(kg2_map[name]) for name in kg2_names]
kg2_emb = model.encode(kg2_texts, convert_to_numpy=True, show_progress_bar=True)

# ======================== ALIGNEMENT ========================
THRESHOLD_FUZZY = 90
THRESHOLD_EMBED = 0.85
stats = {"exact": 0, "fuzzy": 0, "embedding": 0}
matches_list = []
relations_created = 0

print("🚀 Début de l'alignement...")

for i2, name2 in tqdm(enumerate(kg2_names), total=len(kg2_names)):
    n2 = kg2_map[name2]
    emb2 = kg2_emb[i2]

    best_match_name = None
    best_match_method = None
    best_match_score = None

    try:
        # 1. Exact match
        if name2 in kg1_map:
            best_match_name = name2
            best_match_method = "exact"
            best_match_score = 100.0
        else:
            # 2. Fuzzy matching
            best_fuzzy_score = 0
            best_fuzzy_name = None
            for name1 in kg1_names:
                score = fuzz.ratio(name1, name2)
                if score > best_fuzzy_score:
                    best_fuzzy_score = score
                    best_fuzzy_name = name1
                if best_fuzzy_score == 100:
                    break
            if best_fuzzy_score >= THRESHOLD_FUZZY:
                best_match_name = best_fuzzy_name
                best_match_method = "fuzzy"
                best_match_score = float(best_fuzzy_score)
            else:
                # 3. Embedding
                best_emb_score = 0.0
                best_emb_idx = -1
                for i1, emb1 in enumerate(kg1_emb):
                    sim = float(np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2)))
                    if sim > best_emb_score:
                        best_emb_score = sim
                        best_emb_idx = i1
                if best_emb_score >= THRESHOLD_EMBED:
                    best_match_name = kg1_names[best_emb_idx]
                    best_match_method = "embedding"
                    best_match_score = float(round(best_emb_score * 100, 2))

        # Insertion dans Neo4j
        if best_match_name:
            n1 = kg1_map[best_match_name]
            rel_exists = graph.run("""
                MATCH (a:CVE)-[:SAME_AS]-(b:CVE)
                WHERE a.id = $id1 AND b.id = $id2
                RETURN count(*) as c
            """, id1=n1.identity, id2=n2.identity).evaluate()

            if not rel_exists:
                rel = Relationship(n1, "SAME_AS", n2,
                                   method=best_match_method,
                                   score=best_match_score)
                graph.merge(rel)
                relations_created += 1
                matches_list.append([n1["name"], n2["name"], best_match_method, best_match_score])
                stats[best_match_method] += 1
                print(f"🔗 SAME_AS ({best_match_method} - {best_match_score}): {n1['name']} ↔ {n2['name']}")

    except Exception as e:
        print(f"⚠️ Erreur sur {name2} : {e}")

print(f"\n✅ Alignement terminé avec {relations_created} relations SAME_AS créées.")
print("\n📊 Statistiques :")
for k, v in stats.items():
    print(f"   • {k:<9}: {v}")

# ======================== PROPAGATION IMPACTS ========================
def propagate_impacts():
    graph.run("""
    MATCH (h:Host)-[:HAS_PLUGIN]->(:Plugin)-[:DETECTS]->(c:CVE)-[:SAME_AS]-(c2:CVE)<-[:IMPACTS]-(s:Service)
    MERGE (h)-[r:IMPACTS]->(s)
    ON CREATE SET r.inferred = true, r.weight = c2.cvss_score
    ON MATCH SET r.weight = coalesce(r.weight, 0) + coalesce(c2.cvss_score, 0)
    """)
    print("🔁 Propagation IMPACTS terminée.")

propagate_impacts()

# ======================== EXPORT CSV ========================
os.makedirs("data/predictions", exist_ok=True)
csv_filename = "data/predictions/aligned_cves.csv"
with open(csv_filename, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["CVE_KG1", "CVE_KG2", "method", "score"])
    writer.writerows(matches_list)

print(f"📄 Alignements exportés dans {csv_filename}")

# ======================== STATISTIQUES NEO4J ========================
total_same_as = graph.run("MATCH ()-[r:SAME_AS]->() RETURN count(r) AS total").evaluate()
print(f"📈 Relations SAME_AS totales en base : {total_same_as}")
for m in stats.keys():
    count_m = graph.run("MATCH ()-[r:SAME_AS]->() WHERE r.method = $m RETURN count(r) AS total", m=m).evaluate()
    print(f"   • {m:<9}: {count_m}")

