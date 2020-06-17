#!/usr/bin/python

raw = ""
with open("addTwo.wasm", "rb") as f:
    raw = f.read()

payload = ""
payload += "const wasm_code = new Uint8Array(["
for i in raw:
    payload += str(ord(i))
    payload += ","
payload = payload[:-1]
payload += "]);"

print payload