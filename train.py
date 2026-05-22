import torch
import torch.nn as nn
from torch.nn import functional as F
import os
import regex as re
import json
import pickle

# ============================================================
# STEP 0: Create folders if they don't exist
# ============================================================
os.makedirs(os.path.join("data", "pretrain"), exist_ok=True)
os.makedirs(os.path.join("data", "sft"), exist_ok=True)

# ============================================================
# STEP 1: Load pretraining data
# ============================================================
pretrain_path = os.path.join("data", "pretrain", "all_python.txt")
with open(pretrain_path, "r", encoding="utf-8") as f:
    text = f.read()
tokens = list(text.encode('utf-8'))
print(f"Loaded {len(text)} characters, {len(tokens)} bytes")

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
# STEP 3: Train BPE tokenizer on code (or load saved)
# ============================================================
vocab_size = 4096
num_merges = vocab_size - 256

merges_path = os.path.join("data", "merges.pkl")
encoded_data_path = os.path.join("data", "pretrain", "encoded_data.pt")

if os.path.exists(merges_path):
    print("Loading saved merges...")
    with open(merges_path, "rb") as f:
        merges = pickle.load(f)
    print(f"Loaded {len(merges)} merges")
else:
    print("Training BPE tokenizer...")
    ids = list(tokens)
    merges = {}
    for i in range(num_merges):
        stats = get_stats(ids)
        pair = max(stats, key=stats.get)
        idx = 256 + i
        if i % 500 == 0:
            print(f"  Merge {i}/{num_merges}")
        ids = merge(ids, pair, idx)
        merges[pair] = idx

    print("token length:", len(tokens))
    print("ids length:", len(ids))
    print(f"compression ratio: {len(ids) / len(tokens):.2f}")

    with open(merges_path, "wb") as f:
        pickle.dump(merges, f)
    print(f"Saved merges to {merges_path}")

# ============================================================
# STEP 4: Regex pattern + encode/decode (FAST VERSION)
# ============================================================
pat = re.compile(r"""'s|'t|'re|'ve|'m|'ll|'d| ?[a-zA-Z]+| ?[0-9]+| ?[^\s a-zA-Z0-9]+|\s+(?!\S)|\s+""", re.IGNORECASE)

def encode(text):
    chunks = re.findall(pat, text)
    all_tokens = []
    for chunk in chunks:
        chunk_bytes = list(chunk.encode('utf-8'))
        while len(chunk_bytes) >= 2:
            stats = get_stats(chunk_bytes)
            pair = min(stats, key=lambda p: merges.get(p, float('inf')))
            if pair not in merges:
                break
            idx = merges[pair]
            chunk_bytes = merge(chunk_bytes, pair, idx)
        all_tokens.extend(chunk_bytes)
    return all_tokens

def decode(ids):
    vocab = {i: bytes([i]) for i in range(256)}
    for (p0, p1), idx in sorted(merges.items(), key=lambda x: x[1]):
        vocab[idx] = vocab[p0] + vocab[p1]
    raw = b"".join(vocab.get(i, b"?") for i in ids)
    return raw.decode('utf-8', errors='replace')

# ============================================================
# STEP 5: Encode data (or load saved) — with progress
# ============================================================
if os.path.exists(encoded_data_path):
    print("Loading saved encoded data...")
    data = torch.load(encoded_data_path, weights_only=True)
    print(f"Loaded {len(data)} tokens")
else:
    print("Encoding training data...")
    chunk_size = 50000
    all_tokens = []
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size]
        all_tokens.extend(encode(chunk))
        pct = min(100, int((i + chunk_size) / len(text) * 100))
        print(f"  {pct}% done... ({len(all_tokens)} tokens so far)")
    data = torch.tensor(all_tokens, dtype=torch.long)
    torch.save(data, encoded_data_path)
    print(f"Encoded and saved {len(data)} tokens")

# ============================================================
# STEP 6: Hyperparameters
# ============================================================
batch_size = 32
seq_length = 256
device = 'cuda' if torch.cuda.is_available() else 'cpu'
print(f"Device: {device}")

# ============================================================
# STEP 7: get_batch
# ============================================================
def get_batch():
    ix = torch.randint(len(data) - seq_length, (batch_size,))
    x = torch.stack([data[i:i + seq_length] for i in ix])
    y = torch.stack([data[i + 1:i + seq_length + 1] for i in ix])
    return x.to(device), y.to(device)

# ============================================================
# STEP 8: Model
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
# STEP 9: Create model + optimizer
# ============================================================
model = SimpleTransformer(
    vocab_size=vocab_size,
    embed_dim=256,
    num_heads=4,
    num_layers=4
).to(device)

param_count = sum(p.numel() for p in model.parameters())
print(f"Model parameters: {param_count:,} ({param_count/1e6:.2f}M)")

optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4)

def forward_pass(model, x, y):
    logits = model(x)
    B, T, C = logits.size()
    loss = F.cross_entropy(logits.view(B * T, C), y.view(B * T))
    return loss

# ============================================================
# STEP 10: Pretrain on raw code
# ============================================================
pretrained_model_path = os.path.join("data", "pretrained_model.pt")

if os.path.exists(pretrained_model_path):
    print("Loading saved pretrained model...")
    model.load_state_dict(torch.load(pretrained_model_path, map_location=device, weights_only=True))
    print("Loaded pretrained model — skipping pretraining")
else:
    print("\nStarting pretraining...")
    for step in range(5000):
        x, y = get_batch()
        loss = forward_pass(model, x, y)
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        optimizer.step()

        if step % 500 == 0:
            print(f"Step {step}, Loss: {loss.item():.4f}")

    print(f"Final loss: {loss.item():.4f}")
    torch.save(model.state_dict(), pretrained_model_path)
    print("Saved pretrained model")

# ============================================================
# STEP 11: Test generation
# ============================================================
print("\n" + "=" * 60)
print("GENERATING CODE")
print("=" * 60)

model.eval()
with torch.no_grad():
    prompt = "def "
    encoded_prompt = torch.tensor(encode(prompt), dtype=torch.long).unsqueeze(0).to(device)
    generated_ids = model.generate(encoded_prompt, max_new_tokens=200)
    generated_text = decode(generated_ids[0].tolist())
    print(f'Prompt: "{prompt}"')
    print(f"Generated:\n{generated_text}")

    print("\n" + "=" * 60)
    prompt2 = "import "
    encoded_prompt2 = torch.tensor(encode(prompt2), dtype=torch.long).unsqueeze(0).to(device)
    generated_ids2 = model.generate(encoded_prompt2, max_new_tokens=200)
    generated_text2 = decode(generated_ids2[0].tolist())
    print(f'Prompt: "{prompt2}"')
    print(f"Generated:\n{generated_text2}")

    print("\n" + "=" * 60)
    prompt3 = "class "
    encoded_prompt3 = torch.tensor(encode(prompt3), dtype=torch.long).unsqueeze(0).to(device)
    generated_ids3 = model.generate(encoded_prompt3, max_new_tokens=200)
    generated_text3 = decode(generated_ids3[0].tolist())
    print(f'Prompt: "{prompt3}"')
    print(f"Generated:\n{generated_text3}")

# ============================================================
# STEP 12: Load SFT data
# ============================================================
def load_sft_data(path):
    pairs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                pairs.append(json.loads(line))
    return pairs

sft_path = os.path.join("data", "sft", "vuln_pairs.jsonl")
if not os.path.exists(sft_path):
    print(f"\nWARNING: SFT data not found at {sft_path}")
    print("Put vuln_pairs.jsonl in data/sft/ and re-run to do SFT training")
else:
    sft_data = load_sft_data(sft_path)
    print(f"\nLoaded {len(sft_data)} SFT training pairs")

    # ============================================================
    # STEP 13: SFT finetuning
    # ============================================================
    def sft_forward_pass(model, code, report):
        code_ids = torch.tensor(encode(code), dtype=torch.long).unsqueeze(0).to(device)
        report_ids = torch.tensor(encode(report), dtype=torch.long).unsqueeze(0).to(device)
        input_ids = torch.cat((code_ids, report_ids), dim=1)
        # Crop if too long for position embedding
        if input_ids.size(1) > 511:
            input_ids = input_ids[:, :511]
        target_ids = input_ids[:, 1:].contiguous()
        input_ids = input_ids[:, :-1].contiguous()
        logits = model(input_ids)
        B, T, C = logits.size()
        loss = F.cross_entropy(logits.view(B * T, C), target_ids.view(B * T))
        return loss

    print("\nStarting SFT training...")
    model.train()
    sft_optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4)

    for epoch in range(30):
        total_loss = 0
        count = 0
        for pair in sft_data:
            code = pair['messages'][0]['content']
            report = pair['messages'][1]['content']
            try:
                loss = sft_forward_pass(model, code, report)
                sft_optimizer.zero_grad(set_to_none=True)
                loss.backward()
                sft_optimizer.step()
                total_loss += loss.item()
                count += 1
            except Exception as e:
                print(f"  Skipped pair: {e}")
                continue
        avg_loss = total_loss / max(count, 1)
        print(f"SFT Epoch {epoch+1}/10, Avg Loss: {avg_loss:.4f}")

    sft_model_path = os.path.join("data", "sft_model.pt")
    torch.save(model.state_dict(), sft_model_path)
    print(f"Saved SFT model to {sft_model_path}")




    # ============================================================
    # STEP 14: Test the scanner
    # ============================================================
    print("\n" + "=" * 60)
    print("TESTING VULNERABILITY SCANNER")
    print("=" * 60)

    model.eval()
    test_prompts = [
        'Scan this code:\n```python\nquery = f"SELECT * FROM users WHERE id={user_id}"\ndb.execute(query)\n```',
        'Scan this code:\n```python\nimport os\ndef run(cmd):\n    os.system(cmd)\n```',
        'Scan this code:\n```python\nAPI_KEY = "sk-abc123secret"\n```',
        'Scan this code:\n```python\ndef add(a, b):\n    return a + b\n```',
    ]

    with torch.no_grad():
        for test in test_prompts:
            encoded_test = torch.tensor(encode(test), dtype=torch.long).unsqueeze(0).to(device)
            generated = model.generate(encoded_test, max_new_tokens=150)
            result = decode(generated[0].tolist())
            print(f"\nInput: {test[:80]}...")
            print(f"Output: {result[len(test):]}")
            print("-" * 60)