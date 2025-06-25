# 📊 compare_models.py (compatible avec align_kg.py)
# Objectif : analyser la qualité des alignements SAME_AS entre KG1 et KG2 (NVD ↔ Nessus)

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

# ==================== 1. CHARGEMENT DES ALIGNEMENTS ====================
align_path = "data/predictions/aligned_cves.csv"
if not os.path.exists(align_path):
    raise FileNotFoundError("❌ Fichier aligned_cves.csv introuvable. Exécutez align_kg.py d'abord.")

align_df = pd.read_csv(align_path)
print(f"\n📥 Alignements chargés : {len(align_df)} paires")

# ==================== 2. STATS PAR MÉTHODE ====================
print("\n📊 Méthodes d'alignement (distribution) :")
method_counts = align_df['method'].value_counts()
print(method_counts)

plt.figure()
method_counts.plot(kind="bar", color='cornflowerblue')
plt.title("Distribution des méthodes d'alignement")
plt.ylabel("Nombre de paires")
plt.tight_layout()
os.makedirs("outputs/analysis", exist_ok=True)
plt.savefig("outputs/analysis/alignment_distribution.png")
plt.close()

# ==================== 3. SIMILARITÉ COSINE ====================
print("\n📐 Calcul de la similarité cosine moyenne...")
cosines = []
for _, row in align_df.iterrows():
    if isinstance(row['score'], (float, int)) and row['method'] == 'embedding':
        cosines.append(row['score'] / 100.0)

avg_cosine = np.mean(cosines) if cosines else 0.0
print(f"✅ Similarité cosine moyenne (embedding) : {avg_cosine:.4f}")

# ==================== 4. VISUALISATION t-SNE ====================
print("\n🔍 Visualisation t-SNE des entités alignées...")
from sentence_transformers import SentenceTransformer
from py2neo import Graph, NodeMatcher

# Connexion à Neo4j (si besoin)
uri = os.getenv("NEO4J_URI", "neo4j+s://8d5fbce8.databases.neo4j.io")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM")
graph = Graph(uri, auth=(user, password))
matcher = NodeMatcher(graph)

model = SentenceTransformer("all-mpnet-base-v2")
all_entities = list(set(align_df['CVE_KG1'].tolist() + align_df['CVE_KG2'].tolist()))

texts = []
for eid in all_entities:
    node = matcher.match("CVE", name=eid).first()
    if node:
        texts.append(f"{eid} {node.get('description', '')}")
    else:
        texts.append(eid)

embeddings = model.encode(texts, convert_to_numpy=True)

tsne = TSNE(n_components=2, random_state=42, perplexity=30)
tsne_emb = tsne.fit_transform(embeddings)
plt.figure(figsize=(10, 6))
plt.scatter(tsne_emb[:, 0], tsne_emb[:, 1], s=8, alpha=0.6)
plt.title("t-SNE des entités alignées (Sentence-BERT)")
plt.tight_layout()
plt.savefig("outputs/analysis/tsne_embeddings.png")
plt.close()

# ==================== 5. CLUSTERING ET SCORE SILHOUETTE ====================
print("\n🔗 KMeans + silhouette score...")
kmeans = KMeans(n_clusters=5, random_state=42).fit(embeddings)
sil_score = silhouette_score(embeddings, kmeans.labels_)
print(f"🎯 Silhouette Score : {sil_score:.4f}")

# ==================== 6. EXPORT DES RÉSULTATS ====================
with open("outputs/analysis/summary.txt", "w") as f:
    f.write("# Évaluation des alignements SAME_AS\n")
    f.write(f"\n- Nombre total d'alignements : {len(align_df)}")
    f.write(f"\n- Similarité cosine moyenne (embedding) : {avg_cosine:.4f}")
    f.write(f"\n- Silhouette Score (k=5) : {sil_score:.4f}\n")

print("\n✅ Analyse terminée. Export dans outputs/analysis/")
