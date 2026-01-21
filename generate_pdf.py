from markdown import markdown
from weasyprint import HTML

INPUT_MD = "index.md"
OUTPUT_PDF = "weekly-report.pdf"

with open(INPUT_MD, "r", encoding="utf-8") as f:
    md_content = f.read()

html_content = f"""
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    h1, h2 {{ color: #b30000; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; }}
    th {{ background-color: #f2f2f2; }}
  </style>
</head>
<body>
{markdown(md_content, extensions=['tables'])}
</body>
</html>
"""

HTML(string=html_content).write_pdf(OUTPUT_PDF)

print("PDF generated:", OUTPUT_PDF)
