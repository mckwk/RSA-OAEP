# RSA-OAEP Encryption & Decryption

## Goal
Understand and implement RSA with Optimal Asymmetric Encryption Padding (OAEP).

## Subtasks
1. **Easy**: Describe and visualize the OAEP scheme step-by-step.
2. **Medium**: Implement OAEP encoding/decoding using SHA-256 and MGF1.
3. **Hard**: Complete full RSA-OAEP encryption/decryption of a 128-bit AES key.
4. **Extra**: Make OAEP modular so you can swap hash functions or change the seed.
5. **Bonus**: Analyze the difference in security between PKCS#1 v1.5 and OAEP.




## Easy: Describe and visualize the OAEP scheme step-by-step

### Step-by-Step Description of OAEP Scheme
1. **Message Padding**:  
   The input message `M` is padded to a fixed length to ensure it fits the RSA block size.
2. **Split into Two Parts**:  
   The padded message is split into a **data block (DB)** and a **random seed**.
3. **Generate Mask for DB**:  
   Use a Mask Generation Function (MGF1) with the random seed to generate a mask for the data block.
4. **XOR DB with Mask**:  
   XOR the data block with the mask to create a masked data block.
5. **Generate Mask for Seed**:  
   Use MGF1 with the masked data block to generate a mask for the random seed.
6. **XOR Seed with Mask**:  
   XOR the random seed with the mask to create a masked seed.
7. **Concatenate Masked Seed and Masked DB**:  
   Combine the masked seed and masked data block into a single encoded message.
8. **Encrypt with RSA**:  
   Encrypt the encoded message using the RSA public key.

### Visualization of OAEP Encoding

Input Message (M) -> Padding -> Padded Message (PM) PM -> Split -> [Data Block (DB)] + [Random Seed (Seed)]

Seed -> MGF1 -> Mask for DB DB ⊕ Mask -> Masked DB

Masked DB -> MGF1 -> Mask for Seed Seed ⊕ Mask -> Masked Seed

Masked Seed + Masked DB -> Encoded Message Encoded Message -> RSA Encryption -> Ciphertext