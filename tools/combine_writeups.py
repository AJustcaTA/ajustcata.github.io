import os
import re


def get_writeups(base_path):
    writeups = []
    # Categories in preferred order
    categories = ["web", "pwn", "crypto", "rev", "misc"]

    for cat in categories:
        cat_path = os.path.join(base_path, cat)
        if not os.path.exists(cat_path):
            continue

        challenges = sorted(os.listdir(cat_path))
        for chall in challenges:
            chall_path = os.path.join(cat_path, chall)
            if not os.path.isdir(chall_path):
                continue

            # Look for README.md, writeup.md, WRITEUP.md
            found_file = None
            for fname in ["README.md", "writeup.md", "WRITEUP.md"]:
                fpath = os.path.join(chall_path, fname)
                if os.path.isfile(fpath):
                    found_file = fpath
                    break

            if found_file:
                with open(found_file, "r", encoding="utf-8") as f:
                    content = f.read()

                low_content = content.lower()
                if (
                    "two star" in low_content
                    or "2/5 difficulty" in low_content
                    or "★★☆☆☆" in low_content
                    or "2/5" in low_content
                ):
                    continue

                writeups.append(
                    {"category": cat, "challenge": chall, "content": content}
                )

    return writeups


def clean_markdown(content, level_increase=1):
    content = re.sub(r"^---\s*\n.*?\n---\s*\n", "", content, flags=re.DOTALL)

    content = re.sub(r"^#\s+.*$", "", content, flags=re.MULTILINE)

    content = re.sub(
        r"\[Flag format is lactf\{.*?\}\.\]", "", content, flags=re.IGNORECASE
    )
    content = re.sub(r"\[Flag format\]", "", content, flags=re.IGNORECASE)
    content = re.sub(r"\[Files provided\]", "", content, flags=re.IGNORECASE)
    content = re.sub(r"\[Files\]", "", content, flags=re.IGNORECASE)

    content = re.sub(
        r"^(Provided|Challenge) files:.*?(\n\n|\n$)",
        "",
        content,
        flags=re.DOTALL | re.MULTILINE | re.IGNORECASE,
    )
    content = re.sub(r"^- `.*?`(\n|$)", "", content, flags=re.MULTILINE)

    def sanitize_links(match):
        text = match.group(1)
        path = match.group(2)
        if path.startswith(("http", "/", "#")):
            return match.group(0)
        return text

    content = re.sub(r"\[(.*?)\]\((.*?)\)", sanitize_links, content)

    def shift_header(match):
        return "#" * (len(match.group(1)) + level_increase) + match.group(2)

    content = re.sub(r"^(#+)(.*)", shift_header, content, flags=re.MULTILINE)
    return content


def main():
    base_dir = "/home/jst/Downloads/ctf/lac_2026"
    writeups = get_writeups(base_dir)

    output = []
    output.append("---")
    output.append("title: LA CTF 2026 - All Solves")
    output.append("date: 2026-02-10 00:01:00 +0800")
    output.append("categories: [Writeups, LA CTF]")
    output.append("tags: [ctf, web, pwn, crypto, rev, misc]")
    output.append("---")
    output.append("\n{% raw %}")
    output.append("\n# LA CTF 2026 Writeups\n")
    output.append(
        "A collection of all my solutions from LA CTF 2026, organized by category.\n"
    )

    current_cat = ""
    for w in writeups:
        if w["category"] != current_cat:
            current_cat = w["category"]
            output.append(f"\n## {current_cat.upper()}\n")
            output.append("---\n")

        output.append(f"\n### [{w['category']}] {w['challenge']}\n")
        output.append(clean_markdown(w["content"]))
        output.append("\n---\n")

    output.append("\n{% endraw %}")

    post_path = "/home/jst/Documents/Web/ajustcata.github.io/_posts/2026-02-10-la-ctf-2026-all-solves.md"
    with open(post_path, "w", encoding="utf-8") as f:
        f.write("\n".join(output))
    print(f"Combined {len(writeups)} writeups into {post_path}")


if __name__ == "__main__":
    main()
