# 📊 compare_models.py — Évaluation des alignements SAME_AS (NVD ↔ Nessus)

import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Compatibilité GitHub Actions
import matplotlib.pyplot as plt
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sentence_transformers import SentenceTransformer
from py2neo import Graph, NodeMatcher

# ========== 1. Connexion à Neo4j ==========
uri = os.getenv("NEO4J_URI", "neo4j+s://8d5fbce8.databases.neo4j.io")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "VpzGP3RDVB7AtQ1vfrQljYUgxw4VBzy0tUItWeRB9CM")
graph = Graph(uri, auth=(user, password))
matcher = NodeMatcher(graph)

# ========== 2. Chargement des alignements ==========
align_path = "data/predictions/aligned_cves.csv"
if not os.path.exists(align_path):
    raise FileNotFoundError("❌ aligned_cves.csv introuvable. Exécutez align_kg.py d'abord.")

align_df = pd.read_csv(align_path)
print(f"\n📥 Alignements chargés : {len(align_df)} paires")

# ========== 3. Statistiques des méthodes ==========
print("\n📊 Méthodes d'alignement (distribution) :")
method_counts = align_df['method'].value_counts()
print(method_counts)

os.makedirs("outputs/analysis", exist_ok=True)
plt.figure()
method_counts.plot(kind="bar", color='cornflowerblue')
plt.title("Distribution des méthodes d'alignement")
plt.ylabel("Nombre de paires")
plt.tight_layout()
plt.savefig("outputs/analysis/alignment_distribution.png")
plt.close()

# ========== 4. Similarité cosine moyenne ==========
print("\n📐 Calcul de la similarité cosine moyenne...")
cosines = [
    row['score'] / 100.0 for _, row in align_df.iterrows()
    if isinstance(row['score'], (float, int)) and row['method'] == 'embedding'
]
avg_cosine = np.mean(cosines) if cosines else 0.0
print(f"✅ Similarité cosine moyenne (embedding) : {avg_cosine:.4f}")

# ========== 5. Embeddings avec Sentence-BERT ==========
print("\n🔍 t-SNE des entités alignées...")
model = SentenceTransformer("all-mpnet-base-v2")

all_entities = list(set(align_df['CVE_KG1'].tolist() + align_df['CVE_KG2'].tolist()))
texts = []
for eid in all_entities:
    node = matcher.match("CVE", name=eid).first()
    description = node["description"] if node and "description" in node else ""
    texts.append(f"{eid} {description}")

embeddings = model.encode(texts, convert_to_numpy=True)

# ========== 6. t-SNE ==========
tsne = TSNE(n_components=2, random_state=42, perplexity=30)
tsne_emb = tsne.fit_transform(embeddings)

plt.figure(figsize=(10, 6))
plt.scatter(tsne_emb[:, 0], tsne_emb[:, 1], s=8, alpha=0.6)
plt.title("t-SNE des entités alignées (Sentence-BERT)")
plt.tight_layout()
plt.savefig("outputs/analysis/tsne_embeddings.png")
plt.close()

# ========== 7. Clustering et silhouette ==========
print("\n🔗 KMeans + silhouette score...")
kmeans = KMeans(n_clusters=5, random_state=42).fit(embeddings)
sil_score = silhouette_score(embeddings, kmeans.labels_)
print(f"🎯 Silhouette Score : {sil_score:.4f}")

# ========== 8. Résumé de l'analyse ==========
summary_path = "outputs/analysis/summary.txt"
with open(summary_path, "w") as f:
    f.write("# Évaluation des alignements SAME_AS\n")
    f.write(f"\n- Nombre total d'alignements : {len(align_df)}")
    f.write(f"\n- Similarité cosine moyenne (embedding) : {avg_cosine:.4f}")
    f.write(f"\n- Silhouette Score (KMeans, k=5) : {sil_score:.4f}\n")

print(f"\n✅ Analyse terminée. Résultats dans {summary_path}")

