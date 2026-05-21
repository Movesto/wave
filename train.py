import torch
import torch.nn as nn
from torch.nn import functional as F
import os
import regex as re
import json

# ============================================================
# STEP 1: Load pretraining data
# ============================================================
with open("data/pretrain/all_python.txt", "r") as f:
    text = f.read()
tokens = list(text.encode('utf-8'))

# ============================================================
# STEP 2: Tokenizer helper functions
# ============================================================
def get_stats(ids):
    counts = {}
    for pair in zip(ids, ids[1:]):
        counts[pair] = counts.get(pair, 0) + 1
    return counts

def merge(ids, pair, idx):
    newids = []
    i = 0
    while i < len(ids):
        if i < len(ids) - 1 and ids[i] == pair[0] and ids[i + 1] == pair[1]:
            newids.append(idx)
            i += 2
        else:
            newids.append(ids[i])
            i += 1
    return newids

# ============================================================
# STEP 3: Train BPE tokenizer on code
# ============================================================
vocab_size = 512
num_merges = vocab_size - 256
ids = list(tokens)

merges = {}
for i in range(num_merges):
    stats = get_stats(ids)
    pair = max(stats, key=stats.get)
    idx = 256 + i
    print(f"Merge {pair} into a new token: {idx}")
    ids = merge(ids, pair, idx)
    merges[pair] = idx

print("token length:", len(tokens))
print("ids length:", len(ids))
print(f"compression ratio: {len(ids) / len(tokens):.2f}")

# ============================================================
# STEP 4: Regex pattern + encode/decode
# ============================================================
pat = re.compile(r"""'s|'t|'re|'ve|'m|'ll|'d| ?[a-zA-Z]+| ?[0-9]+| ?[^\s a-zA-Z0-9]+|\s+(?!\S)|\s+""", re.IGNORECASE)

def encode(text):
    chunks = re.findall(pat, text)
    all_tokens = []
    for chunk in chunks:
        chunk_bytes = list(chunk.encode('utf-8'))
        while True:
            stats = get_stats(chunk_bytes)
            pair = min(merges.keys(), key=lambda p: merges.get(p, float('inf')))
            if pair not in merges:
                break
            idx = merges[pair]
            chunk_bytes = merge(chunk_bytes, pair, idx)
        all_tokens.extend(chunk_bytes)
    return all_tokens

def decode(ids):
    reverse_merges = {v: k for k, v in merges.items()}
    while True:
        new_ids = []
        i = 0
        while i < len(ids):
            if ids[i] in reverse_merges:
                new_ids.extend(reverse_merges[ids[i]])
                i += 1
            else:
                new_ids.append(ids[i])
                i += 1
        if new_ids == ids:
            break
        ids = new_ids
    return bytes(ids).decode('utf-8')

# ============================================================
# STEP 5: Encode data and build get_batch
# ============================================================
data = torch.tensor(encode(text), dtype=torch.long)

batch_size = 32
seq_length = 256
device = 'cuda' if torch.cuda.is_available() else 'cpu'

# ============================================================
# TODO: You need to write get_batch yourself
# It should:
# - Pick random starting positions in data
# - Create x (input) and y (target, shifted by 1)
# - Return both as tensors on the right device
# Hint: you've written this 3 times before (bigram, CodeGPT, exercise)
# ============================================================
def get_batch():
  x = torch.zeros((batch_size, seq_length), dtype=torch.long)
  y = torch.zeros((batch_size, seq_length), dtype=torch.long)
  for i in range(batch_size):
    start_idx = torch.randint(0, len(data) - seq_length - 1, (1,)).item()
    x[i] = data[start_idx:start_idx + seq_length]
    y[i] = data[start_idx + 1:start_idx + seq_length + 1]
  return x.to(device), y.to(device)

# ============================================================
# STEP 6: Model
# ============================================================
class SimpleTransformer(nn.Module):
    def __init__(self, vocab_size, embed_dim, num_heads, num_layers):
        super().__init__()
        self.token_embedding = nn.Embedding(vocab_size, embed_dim)
        self.pos_embedding = nn.Embedding(512, embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(d_model=embed_dim, nhead=num_heads, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.ln_f = nn.LayerNorm(embed_dim)
        self.head = nn.Linear(embed_dim, vocab_size)

    def forward(self, x):
        B, T = x.size()
        token_emb = self.token_embedding(x)
        pos_emb = self.pos_embedding(torch.arange(T, device=x.device))
        x = token_emb + pos_emb
        mask = nn.Transformer.generate_square_subsequent_mask(T, device=x.device)
        x = self.transformer(x, mask=mask)
        x = self.ln_f(x)
        logits = self.head(x)
        return logits

    def generate(self, idx, max_new_tokens):
        for _ in range(max_new_tokens):
            idx_cond = idx[:, -512:]
            logits = self(idx_cond)
            logits = logits[:, -1, :]
            probs = F.softmax(logits, dim=-1)
            idx_next = torch.multinomial(probs, num_samples=1)
            idx = torch.cat((idx, idx_next), dim=1)
        return idx

# ============================================================
# STEP 7: Create model + optimizer
# ============================================================
model = SimpleTransformer(
    vocab_size=vocab_size,
    embed_dim=256,
    num_heads=4,
    num_layers=4
).to(device)

optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4)

def forward_pass(model, x, y):
    logits = model(x)
    B, T, C = logits.size()
    loss = F.cross_entropy(logits.view(B * T, C), y.view(B * T))
    return loss

# ============================================================
# STEP 8: Pretrain on raw code
# ============================================================
# TODO: Write the pretraining loop yourself
# It should:
# - Run for ~5000 steps
# - Call get_batch() each step
# - Call forward_pass to get loss
# - zero_grad, backward, step
# - Print loss every 500 steps
# You've written this loop many times — do it from memory
# ============================================================

# YOUR PRETRAINING LOOP HERE
for step in range(5000):
    x, y = get_batch()
    loss = forward_pass(model, x, y)
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    if step % 500 == 0:
        print(f"Step {step}, Loss: {loss.item():.4f}")

# ============================================================
# STEP 9: Test generation
# ============================================================
# TODO: Test that the model generates recognizable code
# - Start with a prompt like "def "
# - Encode it, run model.generate, decode the result
# ============================================================

# YOUR GENERATION TEST HERE
prompt = "def "
encoded_prompt = torch.tensor(encode(prompt), dtype=torch.long).unsqueeze(0).to(device)
generated_ids = model.generate(encoded_prompt, max_new_tokens=100)
generated_text = decode(generated_ids[0].tolist())
print("Generated code:\n", generated_text)

# ============================================================
# STEP 10: Load SFT data (for later — don't worry about this yet)
# ============================================================
def load_sft_data(path):
    pairs = []
    with open(path, "r") as f:
        for line in f:
            pairs.append(json.loads(line))
    return pairs

# sft_data = load_sft_data("data/sft/vuln_pairs.jsonl")

# ============================================================
# STEP 11: SFT finetuning loop (BUILD THIS AFTER PRETRAINING WORKS)
# This is where you teach the model to respond to
# "scan this code" with vulnerability reports
# ============================================================

# YOUR SFT LOOP HERE (LATER)
def sft_forward_pass(model, code, report):
    code_ids = torch.tensor(encode(code), dtype=torch.long).unsqueeze(0).to(device)
    report_ids = torch.tensor(encode(report), dtype=torch.long).unsqueeze(0).to(device)
    input_ids = torch.cat((code_ids, report_ids), dim=1)
    target_ids = input_ids[:, 1:].contiguous()
    input_ids = input_ids[:, :-1].contiguous()
    logits = model(input_ids)
    B, T, C = logits.size()
    loss = F.cross_entropy(logits.view(B * T, C), target_ids.view(B * T))
    return loss