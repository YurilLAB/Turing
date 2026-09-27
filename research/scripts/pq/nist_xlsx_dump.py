"""Dump every cell of an .xlsx file (NIST "Errata (potential updates)" sheets).

Reads the Office Open XML directly with zipfile + ElementTree (no openpyxl),
so it needs only the standard library. Prints sheet name, cell reference and
value; numbers that look like Excel date serials (40000-50000) are also shown
as calendar dates (Excel epoch 1899-12-30).

Source files: the FIPS 203 / FIPS 204 errata spreadsheets linked from
https://csrc.nist.gov/pubs/fips/203/final and .../204/final ("Documentation").

Usage:
    timeout 60 python research/scripts/pq/nist_xlsx_dump.py FILE.xlsx
"""
import datetime
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

sys.stdout.reconfigure(encoding="utf-8")
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def main(path):
    z = zipfile.ZipFile(path)
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall("m:si", NS):
            shared.append("".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])))
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    names = [s.get("name") for s in wb.find("m:sheets", NS)]
    sheets = sorted(n for n in z.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
    base = datetime.date(1899, 12, 30)
    for idx, sheet in enumerate(sheets):
        print(f"=== sheet {names[idx] if idx < len(names) else sheet}")
        root = ET.fromstring(z.read(sheet))
        for row in root.iter("{%s}row" % NS["m"]):
            cells = []
            for c in row.findall("m:c", NS):
                v = c.find("m:v", NS)
                if v is None:
                    isel = c.find("m:is", NS)
                    val = "".join(t.text or "" for t in isel.iter("{%s}t" % NS["m"])) if isel is not None else ""
                elif c.get("t") == "s":
                    val = shared[int(v.text)]
                else:
                    val = v.text
                    try:
                        f = float(val)
                        if 40000 < f < 50000 and f == int(f):
                            val += f" [{base + datetime.timedelta(days=int(f))}]"
                    except ValueError:
                        pass
                if val:
                    cells.append(f"{c.get('r')}={val}")
            if cells:
                print(" | ".join(cells))


if __name__ == "__main__":
    main(sys.argv[1])
