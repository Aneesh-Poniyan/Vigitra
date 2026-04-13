from features import lookalike_score

tests = [
    "mail.yahoo.com",
    "yahoo.com",
    "docs.google.com", 
    "mail.google.com",
    "teams.microsoft.com",
    "flipkart.com",
    "paypa1-secure-login.xyz",
    "paypa1.com",
    "amaz0n-order.xyz",
    "micros0ft-login.xyz",
    "googIe-login.xyz",
    "sbi-netbanking-verify.tk",
]

print(f"{'DOMAIN':<40} {'SCORE':>6}  BRAND")
print("=" * 65)
for d in tests:
    score, brand = lookalike_score(d)
    status = "SAFE" if score < 0.5 else "PHISH"
    print(f"{d:<40} {score:>6.2f}  {brand or '-':<15} [{status}]")
