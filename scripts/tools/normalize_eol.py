from pathlib import Path

root = Path("..")
changed = []
for p in (Path(".") / root).rglob("*.sh"):
    b = p.read_bytes()
    if b"\r\n" in b:
        p.write_bytes(b.replace(b"\r\n", b"\n"))
        changed.append(str(p))
print("changed", len(changed))
for c in changed:
    print(c)
