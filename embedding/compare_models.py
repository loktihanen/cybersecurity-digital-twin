# embedding/compare_models.py

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import seaborn as sns
import os

# === CONFIGURATION ===
ALIGN_FILE = "data/predictions/aligned_cves.csv"  # Fichier SAME_AS avec scores
ROTATE_EMB_FILE = "data/triples/rotate_entity_embeddings.npy"  # Embeddings RotatE
ENTITY_LABELS_FILE = "data/triples/entity_labels.csv"          # Mappage entités (nom -> id)
OUTPUT_DIR = "outputs/analysis"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === 1. Charger les alignements SAME_AS ===
df_align = pd.read_csv(ALIGN_FILE)
method_counts = df_align["method"].value_counts()
print("\n▶️ Répartition des méthodes d'alignement :")
print(method_counts)

# === 2. Charger les embeddings RotatE ===
entity_emb = np.load(ROTATE_EMB_FILE)
df_labels = pd.read_csv(ENTITY_LABELS_FILE)
id2name = dict(zip(df_labels["id"], df_labels["label"]))
name2id = {v: k for k, v in id2name.items()}

# Filtrer uniquement les entités alignées
aligned_names = set(df_align["CVE_KG1"]).union(set(df_align["CVE_KG2"]))
aligned_ids = [name2id[name] for name in aligned_names if name in name2id]
aligned_emb = entity_emb[aligned_ids]
aligned_labels = [id2name[i] for i in aligned_ids]

# === 3. Similarité cosine moyenne ===
sim_matrix = cosine_similarity(aligned_emb)
mean_sim = np.mean(sim_matrix)
print(f"\n★ Similarité cosine moyenne (alignements) : {mean_sim:.4f}")

# === 4. Clustering et silhouette ===
kmeans = KMeans(n_clusters=5, random_state=42)
labels = kmeans.fit_predict(aligned_emb)
sil_score = silhouette_score(aligned_emb, labels)
print(f"\n✨ Score de silhouette (k=5) : {sil_score:.4f}")

# === 5. t-SNE pour visualisation ===
tsne = TSNE(n_components=2, perplexity=30, random_state=42)
tsne_emb = tsne.fit_transform(aligned_emb)

plt.figure(figsize=(10, 7))
sns.scatterplot(x=tsne_emb[:, 0], y=tsne_emb[:, 1], hue=labels, palette="Set2", s=50)
plt.title("Visualisation t-SNE des CVE alignées")
plt.legend(title="Cluster", loc="best")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "tsne_aligned_embeddings.png"))
plt.show()

# === 6. Export clustering ===
output_csv = os.path.join(OUTPUT_DIR, "aligned_clusters.csv")
pd.DataFrame({"name": aligned_labels, "cluster": labels}).to_csv(output_csv, index=False)
print(f"\n📄 Fichier CSV des clusters : {output_csv}")
print(f"📸 Image t-SNE sauvegardée dans : {OUTPUT_DIR}/tsne_aligned_embeddings.png")
