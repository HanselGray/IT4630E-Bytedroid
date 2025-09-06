# IT4630E-Bytedroid

**Implementation of an Android Malware Detection System Based on Data Extracted from Dalvik Executable Files**

## Overview

This project implements a malware detection system for Android applications by analyzing bytecode extracted from Dalvik Executable (DEX) files. The system uses deep learning techniques, particularly embedding layers initialized from pre-trained Word2Vec models, to detect malicious patterns in Android bytecode.

The core idea is inspired by the paper **[ByteDroid](ByteDroid.pdf)**. However, due to the lack of implementation details in the original paper regarding the construction of the embedding layer, we had to devise our own approach.

---

## Embedding Layer Construction

The paper did not explicitly explain how the embedding layer was built using pre-trained Word2Vec. As a result, we relied on a custom solution based on the publicly available Word2Vec model:

### Word2Vec Model Used

- **Model**: `word2vec-google-news-300`
- **Source**: Pre-trained on Google News dataset
- **Dimension**: 300

### Problem Faced

The `word2vec-google-news-300` model only includes embeddings for alphanumeric characters, including digits `'0'` to `'9'`, but does **not** cover the full range of bytecode values (0–255). This poses a challenge, as Dalvik bytecode includes values beyond this limited range.

### Custom Solution

To overcome this, we synthesized our own weight vector:

- For byte values **0 to 9**: Directly used corresponding embeddings from the Word2Vec model.
- For byte values **10 to 255**: 
  - Generated random embeddings following the same distribution (mean and standard deviation) as the known Word2Vec vectors.
  - Alternatively, initialized them using strategies like:
    - Mean of existing vectors
    - Small random noise around a central embedding
    - Learned from scratch during training

This hybrid initialization allowed the model to have a complete embedding table for all 256 possible bytecode values.

---

## Datasets

We used publicly available datasets curated for Android malware analysis:

- [CIC MalDroid 2020](http://205.174.165.80/CICDataset/MalDroid-2020/Dataset/)
- [CIC MalAnal 2017](http://205.174.165.80/CICDataset/CICMalAnal2017/Dataset/)
- [CICAndAdGMal 2017](http://205.174.165.80/CICDataset/CICAndAdGMal2017/Dataset/)

These datasets include labeled Android applications (benign vs malicious) which were converted into bytecode sequences for training and evaluation.

---

## Key Takeaways

- The lack of complete vocabulary in the pre-trained Word2Vec model required a creative workaround for embedding initialization.
- Custom embeddings enabled the model to fully represent the bytecode range necessary for Android malware detection.
- The methodology provides a flexible way to combine pre-trained embeddings with domain-specific token representations.

## Alternative Approach: PCA for Malware Detection 

As an alternative to our primary solution, we also explored using **Principal Component Analysis (PCA)** on **Dalvik Executable (DEX) bytecode**.  The code for the PCA approach can be found [HERE](/pca_train.ipynb).
This approach improves efficiency and robustness by lowering computational overhead compared to the `word2vec` embedding approach, while still trying maintaining high detection accuracy.  
