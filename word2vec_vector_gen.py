import gc
import numpy as np
# Word2Vec Librari
import gensim.downloader as api
import gensim
from gensim.models import KeyedVectors





# This function trims the synthesize_embedding into P dimension vector
def trim_to_dimensions(embedding): 
    trimmed_embedding = embedding[:P]  # Take the first P elements
    return trimmed_embedding    

def synthesize_embedding(model, number):
    digits = list(str(number))  # Split the number into its digits
    print(digits)
    digit_embeddings = []
    
    for digit in digits:
        if digit in model:
            digit_embeddings.append(model[digit])
        else:
            raise ValueError(f"Embedding for digit '{digit}' not found in the model.")
    
    # Compute the average embedding for the number
    synthesized_embedding = np.mean(digit_embeddings, axis=0)
    
    # Perform trimming to fit the dimenstion P
    synthesized_embedding=trim_to_dimensions(synthesized_embedding)

    return synthesized_embedding

wv = api.load('word2vec-google-news-300')
word_vectors = KeyedVectors(vector_size=P)
embedding_vectors=[]

for bytecode_value in range(0,256):

    bytecode_id = str(bytecode_value)

    bytecode_embedding = synthesize_embedding(wv,bytecode_value)

    embedding_vectors.append(bytecode_embedding)

    print(bytecode_embedding,'\n', bytecode_embedding.shape)
    gc.collect()


# This will be use to create mappings between word2vec value to a bytecode 
BYTECODE_AS_STRINGS = ["".join(str(i)) for i in range(256)]
word_vectors.add_vectors(BYTECODE_AS_STRINGS, embedding_vectors)

word_vectors.save("custom_bytecode_word2vec.kv")

print("Custom Word2Vec model saved successfully.")


# TESTING
loaded_vectors = KeyedVectors.load("custom_bytecode_word2vec.kv")

# Example: Accessing the vector for bytecode "5"
for i in range(5):
    vector_for_5 = loaded_vectors[str(i)]

    bytecode_embedding = synthesize_embedding(wv,i)

    print(f"Vector for bytecode {i}: {vector_for_5}")

    print(f'Synthesized value for bytecode {i}: {bytecode_embedding}')
    gc.collect()