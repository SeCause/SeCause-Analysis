"""Download public source documents into the ignored RAG raw directory."""
from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import urlopen
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2] / 'rag_documents' / 'raw'


def main():
    owasp = ROOT / 'owasp'
    if not list(owasp.glob('*.md')):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['git', 'clone', '--depth', '1',
                            'https://github.com/OWASP/CheatSheetSeries.git', directory], check=True)
            source = Path(directory)
            owasp.mkdir(parents=True, exist_ok=True)
            for path in (source / 'cheatsheets').glob('*.md'):
                shutil.copy2(path, owasp / path.name)
            for path in source.glob('LICENSE*'):
                shutil.copy2(path, owasp / path.name)
    cwe = ROOT / 'cwe' / 'cwe.xml'
    if not cwe.exists():
        with urlopen('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip', timeout=120) as response:
            with ZipFile(BytesIO(response.read())) as archive:
                names = [name for name in archive.namelist() if name.endswith('.xml')]
                if len(names) != 1:
                    raise ValueError('Expected one CWE XML file')
                cwe.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(names[0]) as source, cwe.with_suffix('.tmp').open('wb') as target:
                    shutil.copyfileobj(source, target)
        cwe.with_suffix('.tmp').replace(cwe)
    print('RAG raw sources ready. Run ./scripts/local-stack.sh index-rag to embed and store them.')


if __name__ == '__main__':
    main()
