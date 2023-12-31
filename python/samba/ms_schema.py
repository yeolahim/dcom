# create schema.ldif (as a string) from WSPP documentation
#
# based on minschema.py and minschema_wspp
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Generate LDIF from WSPP documentation."""

import re
import base64
import uuid

bitFields = {}

# ADTS: 2.2.9
# bit positions as labeled in the docs
bitFields["searchflags"] = {
    'fATTINDEX': 31,         # IX
    'fPDNTATTINDEX': 30,     # PI
    'fANR': 29,  # AR
    'fPRESERVEONDELETE': 28,         # PR
    'fCOPY': 27,     # CP
    'fTUPLEINDEX': 26,       # TP
    'fSUBTREEATTINDEX': 25,  # ST
    'fCONFIDENTIAL': 24,     # CF
    'fCONFIDENTAIL': 24,  # typo
    'fNEVERVALUEAUDIT': 23,  # NV
    'fRODCAttribute': 22,    # RO


    # missing in ADTS but required by LDIF
    'fRODCFilteredAttribute': 22,    # RO
    'fRODCFILTEREDATTRIBUTE': 22,  # case
    'fEXTENDEDLINKTRACKING': 21,  # XL
    'fBASEONLY': 20,  # BO
    'fPARTITIONSECRET': 19,  # SE
}

# ADTS: 2.2.10
bitFields["systemflags"] = {
    'FLAG_ATTR_NOT_REPLICATED': 31, 'FLAG_CR_NTDS_NC': 31,     # NR
    'FLAG_ATTR_REQ_PARTIAL_SET_MEMBER': 30, 'FLAG_CR_NTDS_DOMAIN': 30,     # PS
    'FLAG_ATTR_IS_CONSTRUCTED': 29, 'FLAG_CR_NTDS_NOT_GC_REPLICATED': 29,     # CS
    'FLAG_ATTR_IS_OPERATIONAL': 28,     # OP
    'FLAG_SCHEMA_BASE_OBJECT': 27,     # BS
    'FLAG_ATTR_IS_RDN': 26,     # RD
    'FLAG_DISALLOW_MOVE_ON_DELETE': 6,     # DE
    'FLAG_DOMAIN_DISALLOW_MOVE': 5,     # DM
    'FLAG_DOMAIN_DISALLOW_RENAME': 4,     # DR
    'FLAG_CONFIG_ALLOW_LIMITED_MOVE': 3,     # AL
    'FLAG_CONFIG_ALLOW_MOVE': 2,     # AM
    'FLAG_CONFIG_ALLOW_RENAME': 1,     # AR
    'FLAG_DISALLOW_DELETE': 0     # DD
}

# ADTS: 2.2.11
bitFields["schemaflagsex"] = {
    'FLAG_ATTR_IS_CRITICAL': 31
}

# ADTS: 3.1.1.2.2.2
oMObjectClassBER = {
    '1.3.12.2.1011.28.0.702': base64.b64encode(b'\x2B\x0C\x02\x87\x73\x1C\x00\x85\x3E').decode('utf8'),
    '1.2.840.113556.1.1.1.12': base64.b64encode(b'\x2A\x86\x48\x86\xF7\x14\x01\x01\x01\x0C').decode('utf8'),
    '2.6.6.1.2.5.11.29': base64.b64encode(b'\x56\x06\x01\x02\x05\x0B\x1D').decode('utf8'),
    '1.2.840.113556.1.1.1.11': base64.b64encode(b'\x2A\x86\x48\x86\xF7\x14\x01\x01\x01\x0B').decode('utf8'),
    '1.3.12.2.1011.28.0.714': base64.b64encode(b'\x2B\x0C\x02\x87\x73\x1C\x00\x85\x4A').decode('utf8'),
    '1.3.12.2.1011.28.0.732': base64.b64encode(b'\x2B\x0C\x02\x87\x73\x1C\x00\x85\x5C').decode('utf8'),
    '1.2.840.113556.1.1.1.6': base64.b64encode(b'\x2A\x86\x48\x86\xF7\x14\x01\x01\x01\x06').decode('utf8')
}

# separated by commas in docs, and must be broken up
multivalued_attrs = set(["auxiliaryclass", "maycontain", "mustcontain", "posssuperiors",
                         "systemauxiliaryclass", "systemmaycontain", "systemmustcontain",
                         "systemposssuperiors"])


def __read_folded_line(f, buffer):
    """ reads a line from an LDIF file, unfolding it"""
    line = buffer

    attr_type_re = re.compile("^([A-Za-z][A-Za-z0-9-]*[A-Za-z0-9])::?")

    while True:
        l = f.readline()

        if l[:1] == " ":
            # continued line

            # cannot fold an empty line
            assert(line != "" and line != "\n")

            # preserves '\n '
            line = line + l
        else:
            # non-continued line
            if line == "":
                line = l

                if l == "":
                    # eof, definitely won't be folded
                    break
            else:
                if l[:1] != "#" and l != "\n" and l != "":
                    m = attr_type_re.match(l)
                    if not m:
                        line = line + " " + l
                        continue

                # marks end of a folded line
                # line contains the now unfolded line
                # buffer contains the start of the next possibly folded line
                buffer = l
                break

    return (line, buffer)


def __read_raw_entries(f):
    """reads an LDIF entry, only unfolding lines"""
    import sys

    # will not match options after the attribute type
    # attributes in the schema definition have at least two chars
    attr_type_re = re.compile("^([A-Za-z][A-Za-z0-9-]*[A-Za-z0-9])::?")

    buffer = ""

    while True:
        entry = []

        while True:
            (l, buffer) = __read_folded_line(f, buffer)

            if l[:1] == "#":
                continue

            if l == "\n" or l == "":
                break

            m = attr_type_re.match(l)

            if m:
                if l[-1:] == "\n":
                    l = l[:-1]

                entry.append(l)
            else:
                print("Invalid line: %s" % l, end=' ', file=sys.stderr)
                sys.exit(1)

        if len(entry):
            yield entry

        if l == "":
            break


def fix_dn(dn):
    """fix a string DN to use ${SCHEMADN}"""

    # folding?
    if dn.find("<RootDomainDN>") != -1:
        dn = dn.replace("\n ", "")
        dn = dn.replace(" ", "")
        return dn.replace("CN=Schema,CN=Configuration,<RootDomainDN>", "${SCHEMADN}")
    elif dn.endswith("DC=X"):
        return dn.replace("CN=Schema,CN=Configuration,DC=X", "${SCHEMADN}")
    elif dn.endswith("CN=X"):
        return dn.replace("CN=Schema,CN=Configuration,CN=X", "${SCHEMADN}")
    else:
        return dn


def __convert_bitfield(key, value):
    """Evaluate the OR expression in 'value'"""
    assert(isinstance(value, str))

    value = value.replace("\n ", "")
    value = value.replace(" ", "")

    try:
        # some attributes already have numeric values
        o = int(value)
    except ValueError:
        o = 0
        flags = value.split("|")
        for f in flags:
            bitpos = bitFields[key][f]
            o = o | (1 << (31 - bitpos))

    return str(o)


def __write_ldif_one(entry):
    """Write out entry as LDIF"""
    out = []

    for l in entry:
        if isinstance(l[1], str):
            vl = [l[1]]
        else:
            vl = l[1]

        if l[2]:
            out.append("%s:: %s" % (l[0], l[1]))
            continue

        for v in vl:
            out.append("%s: %s" % (l[0], v))

    return "\n".join(out)


def __transform_entry(entry, objectClass):
    """Perform transformations required to convert the LDIF-like schema
       file entries to LDIF, including Samba-specific stuff."""

    entry = [l.split(":", 1) for l in entry]

    cn = ""
    skip_dn = skip_objectclass = skip_admin_description = skip_admin_display_name = False

    for l in entry:
        if l[1].startswith(': '):
            l.append(True)
            l[1] = l[1][2:]
        else:
            l.append(False)

        key = l[0].lower()
        l[1] = l[1].lstrip()
        l[1] = l[1].rstrip()

        if not cn and key == "cn":
            cn = l[1]

        if key in multivalued_attrs:
            # unlike LDIF, these are comma-separated
            l[1] = l[1].replace("\n ", "")
            l[1] = l[1].replace(" ", "")

            l[1] = l[1].split(",")

        if key in bitFields:
            l[1] = __convert_bitfield(key, l[1])

        if key == "omobjectclass":
            if not l[2]:
                l[1] = oMObjectClassBER[l[1].strip()]
                l[2] = True

        if isinstance(l[1], str):
            l[1] = fix_dn(l[1])

        if key == 'dn':
            skip_dn = True
            dn = l[1]

        if key == 'objectclass':
            skip_objectclass = True
        elif key == 'admindisplayname':
            skip_admin_display_name = True
        elif key == 'admindescription':
            skip_admin_description = True

    assert(cn)

    header = []
    if not skip_dn:
        header.append(["dn", "CN=%s,${SCHEMADN}" % cn, False])
    else:
        header.append(["dn", dn, False])

    if not skip_objectclass:
        header.append(["objectClass", ["top", objectClass], False])
    if not skip_admin_description:
        header.append(["adminDescription", cn, False])
    if not skip_admin_display_name:
        header.append(["adminDisplayName", cn, False])

    header.append(["objectGUID", str(uuid.uuid4()), False])

    entry = header + [x for x in entry if x[0].lower() not in set(['dn', 'changetype', 'objectcategory'])]

    return entry


def __parse_schema_file(filename, objectClass):
    """Load and transform a schema file."""

    out = []

    from io import open
    with open(filename, "r", encoding='latin-1') as f:
        for entry in __read_raw_entries(f):
            out.append(__write_ldif_one(__transform_entry(entry, objectClass)))

    return "\n\n".join(out)


def read_ms_schema(attr_file, classes_file, dump_attributes=True, dump_classes=True, debug=False):
    """Read WSPP documentation-derived schema files."""

    attr_ldif = ""
    classes_ldif = ""

    if dump_attributes:
        attr_ldif = __parse_schema_file(attr_file, "attributeSchema")
    if dump_classes:
        classes_ldif = __parse_schema_file(classes_file, "classSchema")

    return attr_ldif + "\n\n" + classes_ldif + "\n\n"


if __name__ == '__main__':
    import sys

    try:
        attr_file = sys.argv[1]
        classes_file = sys.argv[2]
    except IndexError:
        print("Usage: %s attr-file.txt classes-file.txt" % (sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    print(read_ms_schema(attr_file, classes_file))
