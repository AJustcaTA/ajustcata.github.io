import os
import re

def get_writeups(base_path):
    writeups = []
    challenges = sorted(os.listdir(base_path))
    
    for chall in challenges:
        chall_path = os.path.join(base_path, chall)
        if not os.path.isdir(chall_path):
            continue
        
        found_file = None
        for fname in ['WRITEUP.md', 'writeup.md', 'README.md']:
            fpath = os.path.join(chall_path, fname)
            if os.path.isfile(fpath):
                found_file = fpath
                break
        
        if found_file:
            with open(found_file, 'r', encoding='utf-8') as f:
                content = f.read()
            writeups.append({
                'challenge': chall,
                'content': content
            })
    return writeups

def clean_markdown(content, level_increase=1):
    # Remove YAML front matter
    content = re.sub(r'^---\s*\n.*?\n---\s*\n', '', content, flags=re.DOTALL)
    # Remove top level H1
    content = re.sub(r'^#\s+.*$', '', content, flags=re.MULTILINE)
    
    # Remove relative links
    def sanitize_links(match):
        text = match.group(1)
        path = match.group(2)
        if path.startswith(('http', '/', '#')):
            return match.group(0)
        return text
    content = re.sub(r'\[(.*?)\]\((.*?)\)', sanitize_links, content)

    # Shift headers
    def shift_header(match):
        return '#' * (len(match.group(1)) + level_increase) + match.group(2)
    content = re.sub(r'^(#+)(.*)', shift_header, content, flags=re.MULTILINE)
    
    return content

def main():
    base_dir = '/home/jst/Downloads/ctf/uoftctf/uoftctf'
    writeups = get_writeups(base_dir)
    
    output = []
    output.append("---")
    output.append("title: UofTCTF - Digital Chronicles")
    output.append("date: 2026-02-10 01:02:00 +0800")
    output.append("categories: [Writeups, UofTCTF]")
    output.append("tags: [ctf, uoftctf, reverse, misc, osint]")
    output.append("---")
    
    output.append("\n{% raw %}")
    output.append("\n# 🕵️ UofTCTF Digital Chronicles\n")
    output.append("> \"In the world of binary and obfuscation, the truth is often hidden in plain sight. These are the chronicles of my journey through UofTCTF, where every line of code tells a story and every solved enigma is a step forward in the digital abyss.\"\n")
    output.append("\nA comprehensive collection of my solutions and technical insights from the UofTCTF event.\n")
    
    for w in writeups:
        output.append(f"\n## 🛠️ {w['challenge']}\n")
        output.append("---\n")
        output.append(clean_markdown(w['content']))
        output.append("\n---\n")
        
    output.append("\n{% endraw %}")
    
    post_path = '/home/jst/Documents/Web/ajustcata.github.io/_posts/2026-02-10-uoftctf-digital-chronicles.md'
    with open(post_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output))
    print(f"Combined {len(writeups)} writeups into {post_path}")

if __name__ == "__main__":
    main()
