# RAG Source Documents

Raw source documents are intentionally not committed.

Prepare local source files with this layout before running indexing or preview scripts:

```text
rag_documents/
  raw/
    cwe/
      cwe.xml
    owasp/
      *.md
      LICENSE.md
```

Sources:

- CWE: download the XML data from https://cwe.mitre.org/data/downloads
- OWASP Cheat Sheet Series: copy `cheatsheets/*.md` from https://github.com/OWASP/CheatSheetSeries

The indexing pipeline stores searchable chunks and embeddings in PostgreSQL, not in this directory.
