"""Download public source documents into the ignored RAG raw directory."""
from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import urlopen
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2] / 'rag_documents' / 'raw'


def prepare_owasp(raw_root: Path) -> None:
    """Publish a complete download together and preserve user-prepared documents.

    Existing indexable documents are treated as user-managed. New downloads are
    staged on the same filesystem; interrupted directory swaps recover on retry.
    """
    raw_root.mkdir(parents=True, exist_ok=True)
    owasp = raw_root / 'owasp'
    backup = raw_root / '.owasp-backup'
    if backup.exists():
        if not owasp.exists():
            backup.rename(owasp)
        else:
            shutil.rmtree(backup)
    if any(not path.name.upper().startswith('LICENSE') for path in owasp.glob('*.md')):
        return
    with tempfile.TemporaryDirectory(prefix='.owasp-', dir=raw_root) as directory:
        workspace = Path(directory)
        source = workspace / 'checkout'
        staged = workspace / 'ready'
        subprocess.run(['git', 'clone', '--depth', '1',
                        'https://github.com/OWASP/CheatSheetSeries.git', str(source)], check=True)
        documents = list((source / 'cheatsheets').glob('*.md'))
        if not any(not path.name.upper().startswith('LICENSE') for path in documents):
            raise ValueError('Downloaded OWASP checkout has no indexable documents')
        if owasp.exists():
            shutil.copytree(owasp, staged)
        else:
            staged.mkdir()
        for path in [*documents, *source.glob('LICENSE*')]:
            destination = staged / path.name
            if not destination.exists():
                shutil.copy2(path, destination)
        if owasp.exists():
            owasp.rename(backup)
        try:
            staged.rename(owasp)
        except BaseException:
            if backup.exists():
                backup.rename(owasp)
            raise
        if backup.exists():
            shutil.rmtree(backup)


def main():
    prepare_owasp(ROOT)
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
