# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

import io
from struct import pack, unpack
from xml.sax.saxutils import escape

from xml.dom import minidom

######################################################## AXML FORMAT ########################################################
# Translated from http://code.google.com/p/android4me/source/browse/src/android/content/res/AXmlResourceParser.java

UTF8_FLAG = 0x00000100


class StringBlock:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self._cache = {}
        self.header = unpack('<h', buff.read(2))[0]
        self.header_size = unpack('<h', buff.read(2))[0]

        self.chunkSize = unpack('<i', buff.read(4))[0]
        self.stringCount = unpack('<i', buff.read(4))[0]
        self.styleOffsetCount = unpack('<i', buff.read(4))[0]

        self.flags = unpack('<i', buff.read(4))[0]
        self.m_isUTF8 = ((self.flags & UTF8_FLAG) != 0)

        self.stringsOffset = unpack('<i', buff.read(4))[0]
        self.stylesOffset = unpack('<i', buff.read(4))[0]

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_strings = []
        self.m_styles = []

        for i in range(0, self.stringCount):
            self.m_stringOffsets.append(unpack('<i', buff.read(4))[0])

        for i in range(0, self.styleOffsetCount):
            self.m_styleOffsets.append(unpack('<i', buff.read(4))[0])

        size = self.chunkSize - self.stringsOffset
        if self.stylesOffset != 0:
            size = self.stylesOffset - self.stringsOffset

        # FIXME
        if (size % 4) != 0:
            androconf.warning("ooo")

        for i in range(0, size):
            self.m_strings.append(unpack('=b', buff.read(1))[0])

        if self.stylesOffset != 0:
            size = self.chunkSize - self.stylesOffset

            # FIXME
            if (size % 4) != 0:
                androconf.warning("ooo")

            for i in range(0, size / 4):
                self.m_styles.append(unpack('<i', buff.read(4))[0])

    def getRaw(self, idx):
        if idx in self._cache:
            return self._cache[idx]

        if idx < 0 or not self.m_stringOffsets or idx >= len(self.m_stringOffsets):
            return ""

        offset = self.m_stringOffsets[idx]

        if not self.m_isUTF8:
            length = self.getShort2(self.m_strings, offset)
            offset += 2
            self._cache[idx] = self.decode(self.m_strings, offset, length)
        else:
            offset += self.getVarint(self.m_strings, offset)[1]
            varint = self.getVarint(self.m_strings, offset)

            offset += varint[1]
            length = varint[0]

            self._cache[idx] = self.decode2(self.m_strings, offset, length)

        return self._cache[idx]

    def decode(self, array, offset, length):
        length = length * 2
        length = length + length % 2

        data = bytes()

        for i in range(0, length):
            t_data = pack("=b", self.m_strings[offset + i])
            data += t_data
            if data[-2:] == b"\x00\x00":
                break

        end_zero = data.find(b"\x00\x00")
        if end_zero != -1:
            data = data[:end_zero]
        return data.decode('utf-16')

    def decode2(self, array, offset, length):
        data = bytes()

        for i in range(0, length):
            t_data = pack("=b", self.m_strings[offset + i])
            data += t_data
        return data.decode('utf-8')

    def getVarint(self, array, offset):
        val = array[offset]
        more = (val & 0x80) != 0
        val &= 0x7f

        if not more:
            return val, 1
        return val << 8 | array[offset + 1] & 0xff, 2

    def getShort(self, array, offset):
        value = array[offset / 4]
        if ((offset % 4) / 2) == 0:
            return value & 0xFFFF
        else:
            return value >> 16

    def getShort2(self, array, offset):
        return (array[offset + 1] & 0xff) << 8 | array[offset] & 0xff

    def show(self):
        print("StringBlock", hex(self.start), hex(self.header), hex(self.header_size), hex(self.chunkSize), hex(self.stringsOffset), self.m_stringOffsets)
        for i in range(0, len(self.m_stringOffsets)):
            print(i, repr(self.getRaw(i)))

class SV :
    def __init__(self, size, buff) :
        self.__size = size
        self.__value = unpack(self.__size, buff)[0]

    def _get(self) :
        return pack(self.__size, self.__value)

    def __str__(self) :
        return "0x%x" % self.__value

    def __int__(self) :
        return self.__value

    def get_value_buff(self) :
        return self._get()

    def get_value(self) :
        return self.__value

    def set_value(self, attr) :
        self.__value = attr

class BuffHandle:
    def __init__(self, buff):
        self.__buff = buff
        self.__idx = 0

    def size(self):
        return len(self.__buff)

    def set_idx(self, idx):
        self.__idx = idx

    def get_idx(self):
        return self.__idx

    def readNullString(self, size):
        data = self.read(size)
        return data

    def read_b(self, size) :
        return self.__buff[ self.__idx : self.__idx + size ]

    def read_at(self, offset, size):
        return self.__buff[ offset : offset + size ]

    def read(self, size) :
        if isinstance(size, SV) :
            size = size.value

        buff = self.__buff[ self.__idx : self.__idx + size ]
        self.__idx += size

        return buff

    def end(self) :
        return self.__idx == len(self.__buff)

ATTRIBUTE_IX_NAMESPACE_URI  = 0
ATTRIBUTE_IX_NAME           = 1
ATTRIBUTE_IX_VALUE_STRING   = 2
ATTRIBUTE_IX_VALUE_TYPE     = 3
ATTRIBUTE_IX_VALUE_DATA     = 4
ATTRIBUTE_LENGHT            = 5

CHUNK_AXML_FILE             = 0x00080003
CHUNK_RESOURCEIDS           = 0x00080180
CHUNK_XML_FIRST             = 0x00100100
CHUNK_XML_START_NAMESPACE   = 0x00100100
CHUNK_XML_END_NAMESPACE     = 0x00100101
CHUNK_XML_START_TAG         = 0x00100102
CHUNK_XML_END_TAG           = 0x00100103
CHUNK_XML_TEXT              = 0x00100104
CHUNK_XML_LAST              = 0x00100104

START_DOCUMENT              = 0
END_DOCUMENT                = 1
START_TAG                   = 2
END_TAG                     = 3
TEXT                        = 4


class AXMLParser:
    def __init__(self, raw_buff):
        self.reset()

        self.buff = BuffHandle(raw_buff)

        self.buff.read(4)
        self.buff.read(4)

        self.sb = StringBlock(self.buff)

        self.m_resourceIDs = []
        self.m_prefixuri = {}
        self.m_uriprefix = {}
        self.m_prefixuriL = []

        self.visited_ns = []

    def reset(self):
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def next(self):
        self.doNext()
        return self.m_event

    def doNext(self):
        if self.m_event == END_DOCUMENT:
            return

        event = self.m_event

        self.reset()
        while True:
            chunkType = -1

            # Fake END_DOCUMENT event.
            if event == END_TAG:
                pass

            # START_DOCUMENT
            if event == START_DOCUMENT:
                chunkType = CHUNK_XML_START_TAG
            else:
                if self.buff.end():
                    self.m_event = END_DOCUMENT
                    break
                chunkType = unpack('<L', self.buff.read(4))[0]

            if chunkType == CHUNK_RESOURCEIDS:
                chunkSize = unpack('<L', self.buff.read(4))[0]
                # FIXME
                if chunkSize < 8 or chunkSize % 4 != 0:
                    androconf.warning("ooo")

                for i in range(0, int(chunkSize / 4) - 2):
                    self.m_resourceIDs.append(unpack('<L', self.buff.read(4))[0])

                continue

            # FIXME
            if chunkType < CHUNK_XML_FIRST or chunkType > CHUNK_XML_LAST:
                androconf.warning("ooo")

            # Fake START_DOCUMENT event.
            if chunkType == CHUNK_XML_START_TAG and event == -1:
                self.m_event = START_DOCUMENT
                break

            self.buff.read(4)  # /*chunkSize*/
            lineNumber = unpack('<L', self.buff.read(4))[0]
            self.buff.read(4)  # 0xFFFFFFFF

            if chunkType == CHUNK_XML_START_NAMESPACE or chunkType == CHUNK_XML_END_NAMESPACE:
                if chunkType == CHUNK_XML_START_NAMESPACE:
                    prefix = unpack('<L', self.buff.read(4))[0]
                    uri = unpack('<L', self.buff.read(4))[0]

                    self.m_prefixuri[prefix] = uri
                    self.m_uriprefix[uri] = prefix
                    self.m_prefixuriL.append((prefix, uri))
                    self.ns = uri
                else:
                    self.ns = -1
                    self.buff.read(4)
                    self.buff.read(4)
                    (prefix, uri) = self.m_prefixuriL.pop()
                    #del self.m_prefixuri[ prefix ]
                    #del self.m_uriprefix[ uri ]

                continue

            self.m_lineNumber = lineNumber

            if chunkType == CHUNK_XML_START_TAG:
                self.m_namespaceUri = unpack('<L', self.buff.read(4))[0]
                self.m_name = unpack('<L', self.buff.read(4))[0]

                # FIXME
                self.buff.read(4)  # flags

                attributeCount = unpack('<L', self.buff.read(4))[0]
                self.m_idAttribute = (attributeCount >> 16) - 1
                attributeCount = attributeCount & 0xFFFF
                self.m_classAttribute = unpack('<L', self.buff.read(4))[0]
                self.m_styleAttribute = (self.m_classAttribute >> 16) - 1

                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                for i in range(0, attributeCount * ATTRIBUTE_LENGHT):
                    self.m_attributes.append(unpack('<L', self.buff.read(4))[0])

                for i in range(ATTRIBUTE_IX_VALUE_TYPE, len(self.m_attributes), ATTRIBUTE_LENGHT):
                    self.m_attributes[i] = self.m_attributes[i] >> 24

                self.m_event = START_TAG
                break

            if chunkType == CHUNK_XML_END_TAG:
                self.m_namespaceUri = unpack('<L', self.buff.read(4))[0]
                self.m_name = unpack('<L', self.buff.read(4))[0]
                self.m_event = END_TAG
                break

            if chunkType == CHUNK_XML_TEXT:
                self.m_name = unpack('<L', self.buff.read(4))[0]

                # FIXME
                self.buff.read(4)
                self.buff.read(4)

                self.m_event = TEXT
                break

    def getPrefixByUri(self, uri):
        try:
            return self.m_uriprefix[uri]
        except KeyError:
            return -1

    def getPrefix(self):
        try:
            return self.sb.getRaw(self.m_uriprefix[self.m_namespaceUri])
        except KeyError:
            return ''

    def getName(self):
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG) :
            return ''

        return self.sb.getRaw(self.m_name)

    def getText(self) :
        if self.m_name == -1 or self.m_event != TEXT :
            return ''

        return self.sb.getRaw(self.m_name)

    def getNamespacePrefix(self, pos):
        prefix = self.m_prefixuriL[pos][0]
        return self.sb.getRaw(prefix)

    def getNamespaceUri(self, pos):
        uri = self.m_prefixuriL[pos][1]
        return self.sb.getRaw(uri)

    def getXMLNS(self):
        buff = ""
        for i in self.m_uriprefix:
            if i not in self.visited_ns:
                buff += "xmlns:%s=\"%s\"\n" % (self.sb.getRaw(self.m_uriprefix[i]), self.sb.getRaw(self.m_prefixuri[self.m_uriprefix[i]]))
                self.visited_ns.append(i)
        return buff

    def getNamespaceCount(self, pos) :
        pass

    def getAttributeOffset(self, index):
        # FIXME
        if self.m_event != START_TAG:
            androconf.warning("Current event is not START_TAG.")

        offset = index * 5
        # FIXME
        if offset >= len(self.m_attributes):
            androconf.warning("Invalid attribute index")

        return offset

    def getAttributeCount(self):
        if self.m_event != START_TAG:
            return -1

        return len(self.m_attributes) / ATTRIBUTE_LENGHT

    def getAttributePrefix(self, index):
        offset = self.getAttributeOffset(index)
        uri = self.m_attributes[offset + ATTRIBUTE_IX_NAMESPACE_URI]

        prefix = self.getPrefixByUri(uri)

        if prefix == -1:
            return ""

        return self.sb.getRaw(prefix)

    def getAttributeName(self, index) :
        offset = self.getAttributeOffset(index)
        name = self.m_attributes[offset+ATTRIBUTE_IX_NAME]

        if name == -1 :
            return ""

        return self.sb.getRaw( name )

    def getAttributeValueType(self, index) :
        offset = self.getAttributeOffset(index)
        return self.m_attributes[offset+ATTRIBUTE_IX_VALUE_TYPE]

    def getAttributeValueData(self, index) :
        offset = self.getAttributeOffset(index)
        return self.m_attributes[offset+ATTRIBUTE_IX_VALUE_DATA]

    def getAttributeValue(self, index) :
        offset = self.getAttributeOffset(index)
        valueType = self.m_attributes[offset+ATTRIBUTE_IX_VALUE_TYPE]
        if valueType == TYPE_STRING :
            valueString = self.m_attributes[offset+ATTRIBUTE_IX_VALUE_STRING]
            return self.sb.getRaw( valueString )
        # WIP
        return ""
        #int valueData=m_attributes[offset+ATTRIBUTE_IX_VALUE_DATA];
        #return TypedValue.coerceToString(valueType,valueData);

TYPE_ATTRIBUTE          = 2
TYPE_DIMENSION          = 5
TYPE_FIRST_COLOR_INT    = 28
TYPE_FIRST_INT          = 16
TYPE_FLOAT              = 4
TYPE_FRACTION           = 6
TYPE_INT_BOOLEAN        = 18
TYPE_INT_COLOR_ARGB4    = 30
TYPE_INT_COLOR_ARGB8    = 28
TYPE_INT_COLOR_RGB4     = 31
TYPE_INT_COLOR_RGB8     = 29
TYPE_INT_DEC            = 16
TYPE_INT_HEX            = 17
TYPE_LAST_COLOR_INT     = 31
TYPE_LAST_INT           = 31
TYPE_NULL               = 0
TYPE_REFERENCE          = 1
TYPE_STRING             = 3

RADIX_MULTS             =   [ 0.00390625, 3.051758E-005, 1.192093E-007, 4.656613E-010 ]
DIMENSION_UNITS         =   [ "px","dip","sp","pt","in","mm","","" ]
FRACTION_UNITS          =   [ "%","%p","","","","","","" ]

COMPLEX_UNIT_MASK        =   15


class AXMLPrinter:
    def __init__(self, raw_buff):
        self.axml = AXMLParser(raw_buff)
        self.xmlns = False

        self.buff = ''

        while True:
            _type = self.axml.next()
#           print "tagtype = ", _type

            if _type == START_DOCUMENT:
                self.buff += '<?xml version="1.0" encoding="utf-8"?>\n'
            elif _type == START_TAG:
                self.buff += '<' + self.getPrefix(self.axml.getPrefix()) + self.axml.getName() + '\n'
                self.buff += self.axml.getXMLNS()

                for i in range(0, int(self.axml.getAttributeCount())):
                    self.buff += "%s%s=\"%s\"\n" % ( self.getPrefix(
                        self.axml.getAttributePrefix(i) ), self.axml.getAttributeName(i), self._escape( self.getAttributeValue( i ) ) )

                self.buff += '>\n'

            elif _type == END_TAG :
                self.buff += "</%s%s>\n" % ( self.getPrefix( self.axml.getPrefix() ), self.axml.getName() )

            elif _type == TEXT :
                self.buff += "%s\n" % self.axml.getText()

            elif _type == END_DOCUMENT :
                break

    # pleed patch
    def _escape(self, s):
        s = s.replace("&", "&amp;")
        s = s.replace('"', "&quot;")
        s = s.replace("'", "&apos;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        return escape(s)

    def get_buff(self):
        return self.buff

    def get_xml(self):
        return minidom.parseString(self.get_buff()).toprettyxml()

    def get_xml_obj(self):
        return minidom.parseString(self.get_buff())

    def getPrefix(self, prefix):
        if prefix == None or len(prefix) == 0:
            return ''

        return prefix + ':'

    def getAttributeValue(self, index):
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        if _type == TYPE_STRING:
            return self.axml.getAttributeValue(index)

        elif _type == TYPE_ATTRIBUTE:
            return "?%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_REFERENCE:
            return "@%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_FLOAT:
            return "%f" % unpack("=f", pack("=L", _data))[0]

        elif _type == TYPE_INT_HEX:
            return "0x%08X" % _data

        elif _type == TYPE_INT_BOOLEAN:
            if _data == 0:
                return "false"
            return "true"

        elif _type == TYPE_DIMENSION:
            return "%f%s" % (self.complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type == TYPE_FRACTION:
            return "%f%s" % (self.complexToFloat(_data), FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type >= TYPE_FIRST_COLOR_INT and _type <= TYPE_LAST_COLOR_INT:
            return "#%08X" % _data

        elif _type >= TYPE_FIRST_INT and _type <= TYPE_LAST_INT:
            return "%d" % int(_data)

        return "<0x%X, type 0x%02X>" % (_data, _type)

    def complexToFloat(self, xcomplex):
        return (float)(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]

    def getPackage(self, id):
        if id >> 24 == 1:
            return "android:"
        return ""


RES_NULL_TYPE               = 0x0000
RES_STRING_POOL_TYPE        = 0x0001
RES_TABLE_TYPE              = 0x0002
RES_XML_TYPE                = 0x0003

# Chunk types in RES_XML_TYPE
RES_XML_FIRST_CHUNK_TYPE    = 0x0100
RES_XML_START_NAMESPACE_TYPE= 0x0100
RES_XML_END_NAMESPACE_TYPE  = 0x0101
RES_XML_START_ELEMENT_TYPE  = 0x0102
RES_XML_END_ELEMENT_TYPE    = 0x0103
RES_XML_CDATA_TYPE          = 0x0104
RES_XML_LAST_CHUNK_TYPE     = 0x017f

# This contains a uint32_t array mapping strings in the string
# pool back to resource identifiers.  It is optional.
RES_XML_RESOURCE_MAP_TYPE   = 0x0180

# Chunk types in RES_TABLE_TYPE
RES_TABLE_PACKAGE_TYPE      = 0x0200
RES_TABLE_TYPE_TYPE         = 0x0201
RES_TABLE_TYPE_SPEC_TYPE    = 0x0202


class ARSCParser:
    def __init__(self, raw_buff):
        self.buff = bytecode.BuffHandle(raw_buff)
        #print "SIZE", hex(self.buff.size())

        self.header = ARSCHeader(self.buff)
        self.packageCount = unpack('<i', self.buff.read(4))[0]
        #print hex(self.packageCount)

        self.stringpool_main = StringBlock(self.buff)

        header = ARSCHeader(self.buff)
        self.packages = []
        for i in range(0, self.packageCount):
            self.packages.append(ARSCResTablePackage(self.buff))

            self.mTableStrings = StringBlock(self.buff)
            self.mKeyStrings = StringBlock(self.buff)

            #self.stringpool_main.show()
            #self.mTableStrings.show()
            #self.mKeyStrings.show()

            self.types = []
            self.values = {}

            self.mResId = self.packages[0].mResId

            current = self.buff.get_idx()
            while not self.buff.end():
                c_types = []

                header = ARSCHeader(self.buff)
                c_types.append(header)

                if header.type == RES_TABLE_TYPE_SPEC_TYPE:
                    c_types.append(ARSCResTypeSpec(self.buff, self))

                elif header.type == RES_TABLE_TYPE_TYPE:
                    a_res_type = ARSCResType(self.buff, self)

                    if a_res_type.config.get_language() not in self.values:
                        self.values[a_res_type.config.get_language()] = {}
                        self.values[a_res_type.config.get_language()]["public"] = []

                    c_value = self.values[a_res_type.config.get_language()]

                    entries = []
                    for i in range(0, a_res_type.entryCount):
                        self.mResId = self.mResId & 0xffff0000 | i
                        entries.append((unpack('<i', self.buff.read(4))[0], self.mResId))

                    for entry, res_id in entries:
                        if self.buff.end():
                            break

                        if entry != -1:
                            ate = ARSCResTableEntry(self.buff, res_id, self)

                            if ate.is_public() and ate.get_index() != -1:
                                c_value["public"].append((a_res_type.get_type(), ate.get_value(), ate.mResId))
                                #print "public", c_value["public"][-1]

                            if a_res_type.get_type() not in c_value:
                                c_value[a_res_type.get_type()] = []

                            if a_res_type.get_type() == "string":
                                c_value["string"].append((ate.get_value(), ate.get_key_data()))
                            elif a_res_type.get_type() == "id":
                                if not ate.is_complex():
                                    x = [ate.get_value()]
                                    if ate.key.data == 0:
                                        x.append("false")
                                    elif ate.key.data == 1:
                                        x.append("false")

                                    c_value["id"].append(x)

                elif header.type == RES_TABLE_PACKAGE_TYPE:
                    break
                else:
                    androconf.warning("unknown type")
                    break

                current += header.size
                self.buff.set_idx(current)

    def get_locales(self):
        return self.values.keys()

    def get_public_resources(self, locale='\x00\x00'):
        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        for i in self.values[locale]["public"]:
            buff += '<public type="%s" name="%s" id="0x%08x" />\n' % (i[0], i[1], i[2])

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_string_resources(self, locale='\x00\x00'):
        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        for i in self.values[locale]["string"]:
            buff += '<string name="%s">%s</string>\n' % (i[0], i[1])

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_id_resources(self, locale='\x00\x00'):
        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        for i in self.values[locale]["id"]:
            if len(i) == 1:
                buff += '<item type="id" name="%s"/>\n' % (i[0])
            else:
                buff += '<item type="id" name="%s">%s</item>\n' % (i[0], i[1])

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_id(self, rid):
        for i in self.publics:
            if i[0] == rid:
                return i

    def get_string(self, name):
        for i in self.strings:
            if i[0] == name:
                return i


class ARSCHeader:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self.type = unpack('<h', buff.read(2))[0]
        self.header_size = unpack('<h', buff.read(2))[0]
        self.size = unpack('<i', buff.read(4))[0]

        #print "ARSCHeader", hex(self.start), hex(self.type), hex(self.header_size), hex(self.size)


class ARSCResTablePackage:
    def __init__(self, buff):
        start = buff.get_idx()
        self.id = unpack('<i', buff.read(4))[0]
        self.name = buff.readNullString(256)
        self.typeStrings = unpack('<i', buff.read(4))[0]
        self.lastPublicType = unpack('<i', buff.read(4))[0]
        self.keyStrings = unpack('<i', buff.read(4))[0]
        self.lastPublicKey = unpack('<i', buff.read(4))[0]
        self.mResId = self.id << 24

        #print "ARSCResTablePackage", hex(start), hex(self.id), hex(self.mResId), repr(self.name.decode("utf-16", errors='replace')), hex(self.typeStrings), hex(self.lastPublicType), hex(self.keyStrings), hex(self.lastPublicKey)


class ARSCResTypeSpec:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent
        self.id = unpack('<b', buff.read(1))[0]
        self.res0 = unpack('<b', buff.read(1))[0]
        self.res1 = unpack('<h', buff.read(2))[0]
        self.entryCount = unpack('<i', buff.read(4))[0]

        #print "ARSCResTypeSpec", hex(self.start), hex(self.id), hex(self.res0), hex(self.res1), hex(self.entryCount), "table:" + self.parent.mTableStrings.getRaw(self.id - 1)

        self.typespec_entries = []
        for i in range(0, self.entryCount):
            self.typespec_entries.append(unpack('<i', buff.read(4))[0])


class ARSCResType:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent
        self.id = unpack('<b', buff.read(1))[0]
        self.res0 = unpack('<b', buff.read(1))[0]
        self.res1 = unpack('<h', buff.read(2))[0]
        self.entryCount = unpack('<i', buff.read(4))[0]
        self.entriesStart = unpack('<i', buff.read(4))[0]
        self.mResId = (0xff000000 & self.parent.mResId) | self.id << 16
        self.parent.mResId = self.mResId

        #print "ARSCResType", hex(self.start), hex(self.id), hex(self.res0), hex(self.res1), hex(self.entryCount), hex(self.entriesStart), hex(self.mResId), "table:" + self.parent.mTableStrings.getRaw(self.id - 1)

        self.config = ARSCResTableConfig(buff)

    def get_type(self):
        return self.parent.mTableStrings.getRaw(self.id - 1)


class ARSCResTableConfig:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self.size = unpack('<i', buff.read(4))[0]
        self.imsi = unpack('<i', buff.read(4))[0]
        self.locale = unpack('<i', buff.read(4))[0]
        self.screenType = unpack('<i', buff.read(4))[0]
        self.input = unpack('<i', buff.read(4))[0]
        self.screenSize = unpack('<i', buff.read(4))[0]
        self.version = unpack('<i', buff.read(4))[0]

        self.screenConfig = 0
        self.screenSizeDp = 0

        if self.size >= 32:
            self.screenConfig = unpack('<i', buff.read(4))[0]

            if self.size >= 36:
                self.screenSizeDp = unpack('<i', buff.read(4))[0]

        self.exceedingSize = self.size - 36
        if self.exceedingSize > 0:
            androconf.warning("too much bytes !")
            self.padding = buff.read(self.exceedingSize)

        #print "ARSCResTableConfig", hex(self.start), hex(self.size), hex(self.imsi), hex(self.locale), repr(self.get_language()), repr(self.get_country()), hex(self.screenType), hex(self.input), hex(self.screenSize), hex(self.version), hex(self.screenConfig), hex(self.screenSizeDp)

    def get_language(self):
        x = self.locale & 0x0000ffff
        return chr(x & 0x00ff) + chr((x & 0xff00) >> 8)

    def get_country(self):
        x = (self.locale & 0xffff0000) >> 16
        return chr(x & 0x00ff) + chr((x & 0xff00) >> 8)


class ARSCResTableEntry:
    def __init__(self, buff, mResId, parent=None):
        self.start = buff.get_idx()
        self.mResId = mResId
        self.parent = parent
        self.size = unpack('<h', buff.read(2))[0]
        self.flags = unpack('<h', buff.read(2))[0]
        self.index = unpack('<i', buff.read(4))[0]

        #print "ARSCResTableEntry", hex(self.start), hex(self.mResId), hex(self.size), hex(self.flags), hex(self.index), self.is_complex()#, hex(self.mResId)

        if self.flags & 1:
            ARSCComplex(buff, parent)
        else:
            self.key = ARSCResStringPoolRef(buff, self.parent)

    def get_index(self):
        return self.index

    def get_value(self):
        return self.parent.mKeyStrings.getRaw(self.index)

    def get_key_data(self):
        return self.key.get_data_value()

    def is_public(self):
        return self.flags == 0 or self.flags == 2

    def is_complex(self):
        return (self.flags & 1) == 1


class ARSCComplex:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent

        self.id_parent = unpack('<i', buff.read(4))[0]
        self.count = unpack('<i', buff.read(4))[0]

        self.items = []
        for i in range(0, self.count):
            self.items.append((unpack('<i', buff.read(4)), ARSCResStringPoolRef(buff, self.parent)))

        #print "ARSCComplex", hex(self.start), self.id_parent, self.count, repr(self.parent.mKeyStrings.getRaw(self.id_parent))


class ARSCResStringPoolRef:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent

        buff.read(3)
        self.data_type = unpack('<b', buff.read(1))[0]
        self.data = unpack('<i', buff.read(4))[0]

        #print "ARSCResStringPoolRef", hex(self.start), hex(self.data_type), hex(self.data)#, "key:" + self.parent.mKeyStrings.getRaw(self.index), self.parent.stringpool_main.getRaw(self.data)

    def get_data_value(self):
        return self.parent.stringpool_main.getRaw(self.data)
