# Tokens are used to feed the model with information. They can be words, characters, or subwords. The number of tokens in a prompt can affect the model's performance and response time. 
# It's important to keep track of the token count when crafting prompts for language models. Tokens are at the heart of many issues models face such as spelling words, or arithmetic. 
# If a prompt is too long, it may exceed the model's maximum token limit, leading to truncated responses or errors. On the other hand, 
#  if a prompt is too short, it may not provide enough context for the model to generate a meaningful response. 
# BPE will break down words into subwords, which can help the model understand and generate text more effectively, especially for rare or complex words. like aa to z. 



text = "Waxbarashadu waa furaha nolosha. Qof kasta oo raba inuu nolosha ku guulaysto waa inuu waxbarasho wnaagsan helaa. Duniyadda maanta waxaa isbadal weyn ku yimid teknolojiyada iyo sayniska. Dadka waxbarasho leh ayaa fursado badan hela oo ay ku shaqayn karaan meelo kala duwan. Waxbarashadu waxay barataaa dadka sida loo fikiro, sida loola shaqeeyo dadka kale, iyo sida loo xalliyo dhibaatooyinka nolosha Soomaaliya waa dal ku yaal Geeska Afrika. Dadkeeda waa dad nabad jaceel ah oo leh dhaqan iyo caado aad u qurux badan. Luqadda Soomaaliga waxaa lagu qoray xarfaha Laatinka laga bilaabo sanadkii 1972-kii. Intaa ka hor, luqaddu waxay ahayd mid afka lagu sii daayo oo aan la qorin. Maanta, carruurta Soomaaliyeed waxay barashada ku bilowdaan dugsiyada hoose, kadibna waxay u gudbaan dugsiyada sare iyo jaamicadaha.Teknolojiyada cusub waxay baddashay sida aan u noolaano. Telefoonada gacanta, kombuyuutarada, iyo internetka waxay nolosha ka dhigeen mid aad u fududdahay. Dadku waxay hadda isticmaalaan teknolojiyada si ay ugu hadasho ehel iyo saaxiibbo ku nool meelo fog. Waxbarashada online-ka ah waxay siisay fursad cusub dadka raba inay wax bartaan laakiin aan awoodi karin inay iskuulka tagaan. Caafimaadku waa taaj madaxa saaran qofka caafimaadka qaba. Dadku waa inay cuntada caafimaadka ah cunaan, jimicsiga sameeyaan, iyo hurdo ku filan helaan. Biyaha nadiiifka ah iyo hawada saafiga ah waxay muhiim u yihiin caafimaadka dadka. Xanuunada badan waxaa looga hortagi karaa nadaafadda iyo tallaalka. Dhaqanka Soomaalida waa mid aad u qani ah. Suugaanta, heesaha, iyo sheekooyin hooyooyinku carruurta u sheegaan waxay ka mid yihiin hiddaha Soomaalida. Dadku waxay isku yimaadaan xafladaha iyo munaasbadaha si ay u soo dhaweeyaan martida iyo ehelu. Soomaalidu waxay ku caan yihiin marti qaadashada iyo dedaalka ay u galaan inay marti fiican u qaadaan dadka soo booqda. Mustaqbalka waa mid rajo badan leh haddii dadku si wada jir ah u shaqeeyaan. Nabadda, waxbarashada, iyo horumarku waa saddexda tiir ee lagu dhiso bulshada wanaagsan. Qof walba waa inuu qayb ka qaataa horumarinta bulshadiisa. Waxaanu rajaynaynaa in mustaqbalku noqdo mid ka wanaagsan maanta, oo ay carruurteenu ku noolaadaan dunida nabadda iyo barwaaqada."
tokens = text.encode('utf-8')
tokens = list(map(int, tokens))


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

vocab_size = 276
num_merges  = vocab_size - 256
ids = list(tokens)

merges = {} 
for i in range(num_merges):
    stats = get_stats(ids)
    pair = max(stats, key=stats.get)
    idx = 256 + i
    print(f"Merge {pair} into a new token: {idx}")
    ids = merge(ids, pair, idx)
    merges[pair] = idx


print ("token lenght:", len(tokens))
print("ids lenght:", len(ids))
print(f"compression ratio: {len(ids) / len(tokens):.2f}")

def encode(text):
    tokens = list(text.encode('utf-8'))
    while True:
        stats = get_stats(tokens)
        pair = min(merges.keys(), key=lambda p: merges.get(p, float('inf')))
        if pair not in merges:
            break
        idx = merges[pair]
        tokens = merge(tokens, pair, idx)
    return tokens

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



