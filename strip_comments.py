import os, re, glob

def strip_python(content):
    return '\n'.join([l for l in content.split('\n') if not re.match(r'^\s*#', l)])

def strip_js_css(content):
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    return '\n'.join([l for l in content.split('\n') if not re.match(r'^\s*//', l)])

def strip_html(content):
    return re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

for f in glob.glob('**/*.py', recursive=True):
    if 'venv' in f: continue
    if f == 'strip_comments.py': continue
    try:
        with open(f, 'r', encoding='utf-8') as file: c = file.read()
        with open(f, 'w', encoding='utf-8') as file: file.write(strip_python(c))
        print(f"Stripped {f}")
    except Exception as e:
        print(f"Skipped {f}: {e}")

for f in glob.glob('**/*.js', recursive=True) + glob.glob('**/*.css', recursive=True):
    if 'venv' in f: continue
    try:
        with open(f, 'r', encoding='utf-8') as file: c = file.read()
        with open(f, 'w', encoding='utf-8') as file: file.write(strip_js_css(c))
        print(f"Stripped {f}")
    except Exception as e:
        pass

for f in glob.glob('**/*.html', recursive=True):
    if 'venv' in f: continue
    try:
        with open(f, 'r', encoding='utf-8') as file: c = file.read()
        with open(f, 'w', encoding='utf-8') as file: file.write(strip_html(c))
        print(f"Stripped {f}")
    except Exception as e:
        pass

print('All comments stripped.')
