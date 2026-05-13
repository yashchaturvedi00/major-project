import pandas as pd

df = pd.read_csv('Dataset/Attack_Dataset.csv')
df = df.dropna(subset=['Attack Type', 'Category'])

with open('tmp_cats.txt', 'w', encoding='utf-8') as f:
    f.write("ALL UNIQUE CATEGORIES:\n")
    for c in sorted(df['Category'].unique()):
        count = (df['Category'] == c).sum()
        f.write(f"  {c} ({count})\n")
    
    f.write("\n\nATTACK TYPES CONTAINING KEYWORDS:\n")
    keywords = ['Insider', 'Shoulder', 'DDoS', 'Denial', 'Brute', 'Phish',
                'Credential', 'Masquerad', 'Command', 'Script', 'Interpreter']
    for kw in keywords:
        f.write(f"\n--- {kw} ---\n")
        types = df[df['Attack Type'].str.contains(kw, case=False, na=False)]['Attack Type'].unique()
        for t in types[:10]:
            count = (df['Attack Type'] == t).sum()
            f.write(f"  type: {t} ({count})\n")
        cats = df[df['Category'].str.contains(kw, case=False, na=False)]['Category'].unique()
        for c in cats[:5]:
            count = (df['Category'] == c).sum()
            f.write(f"  cat: {c} ({count})\n")

print("Done! Check tmp_cats.txt")
