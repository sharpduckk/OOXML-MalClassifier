from struct import unpack, calcsize
from abc import *
import zlib
import logging
from enum import Enum
from .entropy import entropy

default_logger = logging.getLogger('ZIP')


def hidden_msg(logger, index, header, field_name, field_length_name, class_name, exist_option=False):
    field = header[field_name]
    if header[field_length_name] > 0:
        if exist_option:
            logger.warning("%s in %s(%d) found! (Data: %s)" % (
                field_name, class_name, index, field))
        if b'\x00' in field:
            logger.error("Hidden %s in %s(%d) found! (Data: %s)" % (
                field_name, class_name, index, field.split(b'\x00')[1]))


class Parser(metaclass=ABCMeta):

    struct = {
    }

    def __init__(self, f, struct, logger=default_logger) -> None:
        super().__init__()
        self.logger = logger
        self.start_pos = f.tell()
        self.header = {}
        self.read(f, struct)
        self.validate(f)

    def read(self, f, struct):
        self.header = {}
        for s in struct:
            if struct[s] in struct:
                self.header[s] = f.read(self.header[struct[s]])
            else:
                self.header[s] = unpack(struct[s], f.read(calcsize(struct[s])))[0]

    def size(self):
        return sum([self.header[self.struct[s]] if self.struct[s] in self.struct else calcsize(self.struct[s]) \
                                                          for s in self.struct])

    @abstractmethod
    def validate(self, f):
        pass

    @abstractmethod
    def area(self):
        pass

    def field_offset(self, field_name):
        offset = 0
        for name in self.struct:
            if field_name == name:
                return offset
            offset += self.field_size(name)
        return 0

    def field_size(self, field_name):
        if self.struct[field_name] in self.struct:
            size = self.header[self.struct[field_name]]
        else:
            size = calcsize(self.struct[field_name])
        return size

    def __str__(self) -> str:
        return str(self.header)


class Compression(Enum):
    none = 0
    shrunk = 1
    reduced_1 = 2
    reduced_2 = 3
    reduced_3 = 4
    reduced_4 = 5
    imploded = 6
    deflated = 8
    enhanced_deflated = 9
    pkware_dcl_imploded = 10
    bzip2 = 12
    lzma = 14
    ibm_terse = 18
    ibm_lz77_z = 19
    ppmd = 98


class ExtraCodes(Enum):
    zip64 = 1
    av_info = 7
    os2 = 9
    ntfs = 10
    openvms = 12
    pkware_unix = 13
    file_stream_and_fork_descriptors = 14
    patch_descriptor = 15
    pkcs7 = 20
    x509_cert_id_and_signature_for_file = 21
    x509_cert_id_for_central_dir = 22
    strong_encryption_header = 23
    record_management_controls = 24
    pkcs7_enc_recip_cert_list = 25
    ibm_s390_uncomp = 101
    ibm_s390_comp = 102
    poszip_4690 = 18064
    extended_timestamp = 21589
    infozip_unix = 30805
    infozip_unix_var_size = 30837


class ExtraField(object):
    def __init__(self, data, len) -> None:
        super().__init__()
        self.code = unpack('H', data[:2])[0]
        if self.is_reserved():
            self.size = unpack('H', data[2:4])[0]
            self.body = data[4:self.size]
        else:
            self.body = data[2:len]

    def is_reserved(self):
        return self.code == 41504

    def entropy(self):
        return entropy(self.body[4:])


class LocalFileHeader(Parser):

    struct = {
        "magic": "I",
        "version": "H",
        "flag": "H",
        "compression_method": "H",
        "file_mod_time": "H",
        "file_mod_date": "H",
        "crc32": "I",
        "compressed_size": "I",
        "uncompressed_size": "I",
        "file_name_len": "H",
        "extra_len": "H",
        "file_name": "file_name_len",
        "extra": "extra_len",
        "data": "compressed_size"
    }

    _index = 0

    def __init__(self, f, logger=default_logger) -> None:
        self.index = LocalFileHeader._index
        super().__init__(f, self.struct, logger)
        LocalFileHeader._index += 1
        self.file = f.tell()

    def area(self):
        return (self.start_pos, self.size() + self.header['compressed_size'])

    def end_offset(self):
        return self.start_pos + self.size()

    def validate(self, f):
        hidden_msg(self.logger, self.index, self.header
                   , 'file_name', 'file_name_len', __class__.__name__)

        try:
            Compression(self.header['compression_method'])
        except Exception:
            self.logger.error("Unknown compression method in %s(%d) found!" % (
                __class__.__name__, self.index))

        if self.header["extra_len"] > 0:
            self.logger.warning("Extra Field in %s(%d) found!" % (
                __class__.__name__, self.index))

            if self.header["extra_len"] > 2:
                extra_field = ExtraField(self.header["extra"], self.header["extra_len"])

                try:
                    ExtraCodes(extra_field.code)
                except Exception:
                    self.logger.warning("Unknown code in Extra Field in %s(%d) found!" % (
                        __class__.__name__, self.index))
                    if extra_field.entropy() > 0:
                        self.logger.error("Hidden data in Extra Field in %s(%d) found!" % (
                            __class__.__name__, self.index))

        # File Data Validation
        if self.header['compression_method'] > 0:
            try:
                decompressed_data = self.inflate(self.header['data'])

                if self.header['crc32'] != zlib.crc32(decompressed_data):
                    self.logger.error("CRC32 of %s(%d) is wrong!" % (
                        __class__.__name__, self.index))
                if self.header['uncompressed_size'] != len(decompressed_data):
                    self.logger.error("Uncompressed Size of %s(%d) is wrong!" % (
                        __class__.__name__, self.index))
            except Exception:
                self.logger.error("Data validation of %s(%d) failed!" % (
                    __class__.__name__, self.index))

    def deflate(self, data):
        zlibbed_data = zlib.compress(data)
        # remove byte 0-1(header) and the last four(checksum)
        compressed_data = zlibbed_data[2:-4]
        return compressed_data

    def inflate(self, compressed_data):
        # -15 for the window buffer will make it ignore headers/footers
        zlibbed_data = zlib.decompress(compressed_data, -15)
        return zlibbed_data


class CentralDirectory(Parser):

    struct = {
        "magic": "I",
        "version_made_by": "H",
        "version_needed_to_extract": "H",
        "flags": "H",
        "compression_method": "H",
        "last_mod_file_time": "H",
        "last_mod_file_date": "H",
        "crc32": "I",
        "compressed_size": "I",
        "uncompressed_size": "I",
        "file_name_len": "H",
        "extra_len": "H",
        "comment_len": "H",
        "disk_number_start": "H",
        "int_file_attr": "H",
        "ext_file_attr": "I",
        "local_header_offset": "I",
        "file_name": "file_name_len",
        "extra": "extra_len",
        "comment": "comment_len"
    }

    _index = 0

    def __init__(self, f, logger=default_logger) -> None:
        self.index = CentralDirectory._index
        super().__init__(f, self.struct, logger)
        CentralDirectory._index += 1

    def area(self):
        return (self.start_pos, self.size())

    def end_offset(self):
        return self.start_pos + self.size()

    def validate(self, f):
        hidden_msg(self.logger, self.index, self.header
                   , 'file_name', 'file_name_len', __class__.__name__)

        try:
            Compression(self.header['compression_method'])
        except Exception:
            self.logger.error("Unknown compression method in %s(%d) found!" % (
                __class__.__name__, self.index))

        if self.header["extra_len"] > 0:
            self.logger.warning("Extra Field in %s(%d) found!" % (
                __class__.__name__, self.index))

            if self.header["extra_len"] > 2:
                extra_field = ExtraField(self.header["extra"], self.header["extra_len"])

                try:
                    ExtraCodes(extra_field.code)
                except Exception:
                    self.logger.warning("Unknown code in Extra Field in %s(%d) found!" % (
                        __class__.__name__, self.index))
                    if extra_field.entropy() > 0:
                        self.logger.error("Hidden data in Extra Field in %s(%d) found!" % (
                            __class__.__name__, self.index))

            hidden_msg(self.logger, self.index, self.header
                       , 'comment', 'comment_len', __class__.__name__, True)


class EndOfCentralDirectory(Parser):

    struct = {
        "magic": "I",
        "disk_of_end_of_central_dir": "H",
        "disk_of_central_dir": "H",
        "qty_central_dir_entries_on_disk": "H",
        "qty_central_dir_entries_total": "H",
        "central_dir_size": "I",
        "central_dir_offset": "I",
        "comment_len": "H",
        "comment": "comment_len"
    }

    _index = 0

    def __init__(self, f, logger=default_logger) -> None:
        self.index = EndOfCentralDirectory._index
        super().__init__(f, self.struct, logger)
        EndOfCentralDirectory._index += 1

    def validate(self, f):
        hidden_msg(self.logger, self.index, self.header
                   , 'comment', 'comment_len', __class__.__name__, True)

    def area(self):
        return (self.start_pos, self.size())

    def end_offset(self):
        return self.start_pos + self.size()


class Zip(object):

    Segments = {
        0x04034B50: LocalFileHeader,
        0x02014B50: CentralDirectory,
        0x06054B50: EndOfCentralDirectory
    }

    def __init__(self, file_name, logger=default_logger) -> None:
        super().__init__()

        self.logger = logger
        self.file_name = file_name
        self.all_header = []
        self.local_file_headers = []
        self.central_directories = []
        self.end_of_central_directory = None

        LocalFileHeader._index = 0
        CentralDirectory._index = 0
        EndOfCentralDirectory._index = 0

        self.read()
        self.validate()

    def area(self):
        return self.local_file_headers[0].start_pos, self.end_of_central_directory.start_pos \
               + self.end_of_central_directory.size()

    def read(self):
        with open(self.file_name, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(0)
            pos = 0

            while pos < size - 4:
                i = unpack('i', f.read(4))[0]

                if i in self.Segments:
                    f.seek(pos)
                    header = self.Segments[i](f, self.logger)
                    self.add(header)

                pos += 1
                f.seek(pos)

    def readBytes(self, offset, length):
        with open(self.file_name, 'rb') as f:
            f.seek(offset)
            return f.read(length)

    def add(self, header):
        header_type = type(header)
        if header_type == LocalFileHeader:
            self.local_file_headers.append(header)
        elif header_type == CentralDirectory:
            self.central_directories.append(header)
        elif header_type == EndOfCentralDirectory:
            self.end_of_central_directory = header
        self.all_header.append(header)

    def validate(self):
        start_header_offset = self.local_file_headers[0].start_pos
        if start_header_offset > 0:
            self.logger.error("Inserted data found! (Data: %s)" % self.readBytes(0, start_header_offset))

        lfh_count = len(self.local_file_headers)
        cd_count = len(self.central_directories)
        if lfh_count != cd_count:
            self.logger.error('The number of %s(%d) and %s(%d) is wrong!'
                              % (LocalFileHeader.__name__, lfh_count
                                 , CentralDirectory.__name__, cd_count))

        self.detect_structure_anomaly()
        self.cross_validation()
        self.detect_file_slack()

        eocd_end_offset =  self.end_of_central_directory.end_offset()
        is_file_end = self.get_file_size() == eocd_end_offset
        if not is_file_end:
            self.logger.error("Appended data found! (Data: %s)"
                              % self.readBytes(eocd_end_offset
                                               , self.get_file_size() - eocd_end_offset)[:100])


    def cross_validation(self):
        cd_map = {}
        for c in self.central_directories:
            cd_map[c.header['file_name']] = c

        for l in self.local_file_headers:
            if l.header['file_name'] not in cd_map:
                continue
            cd = cd_map[l.header['file_name']]

            for field_name in l.header:
                if field_name == 'magic' \
                        or field_name == 'extra_len' \
                        or field_name == 'extra':
                    continue
                if field_name in cd.header \
                        and l.header[field_name] != cd.header[field_name]:
                    self.logger.error('%s field of %s(%d) and %s(%d) is wrong!'
                                      % (field_name, LocalFileHeader.__class__.__name__, l.index
                                         , CentralDirectory.__class__.__name__, cd.index))

    def detect_structure_anomaly(self):
        # End of Central Directory
        central_dir_offset = self.end_of_central_directory.header["central_dir_offset"]
        real_central_dir_offset = self.central_directories[0].start_pos
        if central_dir_offset != real_central_dir_offset:
            self.logger.error('CentralDirectory anomaly found.')

        offset_mapping = {}
        for h in self.local_file_headers:
            offset_mapping[h.start_pos] = (h, None)

        for c in self.central_directories:
            offset = c.header["local_header_offset"]
            if offset in offset_mapping:
                if offset_mapping[offset][1] is None:
                    offset_mapping[offset] = (offset_mapping[offset][0], c)
                else:
                    self.logger.error('%s(%d) structure anomaly found.(duplicated)' % (c.__class__.__name__, c.index))
            else:
                self.logger.error('%s(%d) structure anomaly found.(not found LocalFileHeader)'
                                  % (c.__class__.__name__, c.index))

        for o in offset_mapping:
            c = offset_mapping[o][1]
            if c is None:
                h = offset_mapping[o][0]
                self.logger.error('%s(%d) structure anomaly found. (not found CentralDirectory)'
                                  % (h.__class__.__name__, h.index))

    def detect_file_slack(self):
        lfh_count = len(self.local_file_headers)
        data_slack_headers = self.all_header[1:lfh_count + 1]
        prev_header = self.all_header[0]
        prev = prev_header.end_offset()
        for header in data_slack_headers:
            next = header.start_pos
            if prev != next:
                error_msg = 'File data slack in %s(%d) found!' % (prev_header.__class__.__name__, prev_header.index)
                if next - prev > 0:
                    error_msg += " (Data: %s)" % (self.readBytes(prev, next - prev))[:10]
                self.logger.error(error_msg)
            prev_header = header
            prev = header.end_offset()

    def get_file_size(self):
        with open(self.file_name, 'rb') as f:
            pos = f.tell()
            f.seek(0, 2)
            size = f.tell()
            f.seek(pos)
            return size

    def __str__(self) -> str:
        return str(self.local_file_headers) + "\n" \
               + str(self.central_directories) + "\n" \
               + str(self.end_of_central_directory)
