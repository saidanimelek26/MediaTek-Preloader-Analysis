import hashlib
import struct
import sys
import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple, Union
from pathlib import Path


MAX_FILE_SIZE    = 256 * 1024 * 1024
MAX_GFH_HDR_SIZE = 4 * 1024 * 1024

MTK_BLOADER_INFO = b"MTK_BLOADER_INFO_v"
MTK_BIN_MARKER   = b"MTK_BIN"


class MagicTokens:
    GFH_SIGNATURE       = b'MMM'
    GFH_SIGNATURE_DWORD = 0x014D4D4D
    BRLYT_IDENTIFIER    = b'BRLYT\x00\x00\x00'
    BLOCK_EXIST_MARKER  = b'BBBB'
    ANDROID_ROM_INFO    = b'AND_ROMINFO_v'
    ANDROID_SECURITY_CTRL = b'AND_SECCTRL_v'
    ANDROID_SECURITY_KEY  = b'AND_SECRO_v'

    BOOT_DEVICES = {
        b'EMMC_BOOT\x00\x00\x00': 'EMMC_BOOT',
        b'SDMMC_BOOT\x00\x00':    'SDMMC_BOOT',
        b'SF_BOOT\x00\x00\x00\x00\x00': 'SF_BOOT',
    }


class GfhSectionType(Enum):
    FILE_DESCRIPTOR  = 0x0000
    BOOTLOADER_INFO  = 0x0001
    CLONE_PROTECTION = 0x0002
    BOOT_KEY         = 0x0003
    CERTIFICATE      = 0x0004
    AUTH_TOKEN       = 0x0005
    ROM_CONFIG       = 0x0007
    ROM_SECURITY     = 0x0008
    ROOT_OF_TRUST    = 0x000B
    EXPIRY_CHECK     = 0x000C
    PARAMETERS       = 0x000D
    CHIP_REVISION    = 0x000E
    MODEM_CONFIG     = 0x0010
    EMI_LIST         = 0x0101
    MAUI_KEY         = 0x0202


class PayloadType(Enum):
    EMPTY               = 0x0000
    ARM_CODE            = 0x0001
    EXTENDED_ARM        = 0x0002
    SECURITY_CERT       = 0x0004
    AUTH_DATA           = 0x0005
    EXEC_PARAMS         = 0x0007
    TRUST_ANCHOR        = 0x000A
    APPLICATION_PAYLOAD = 0x000B


VALID_PAYLOAD_TYPES = {
    PayloadType.ARM_CODE.value,
    PayloadType.EXTENDED_ARM.value,
    PayloadType.APPLICATION_PAYLOAD.value,
}


class FlashType(Enum):
    NONE            = 0
    NOR             = 1
    NAND_SEQUENTIAL = 2
    NAND_TABLE      = 3
    NAND_DMA        = 4
    EMMC_BOOT       = 5
    EMMC_DATA       = 6
    SERIAL_FLASH    = 7
    XBOOT           = 8


class SigType(Enum):
    NONE              = 0
    PHASH             = 1
    SINGLE            = 2
    SINGLE_AND_PHASH  = 3
    MULTI             = 4


class SecStatus(Enum):
    DISABLE              = 0x00
    ENABLE               = 0x11
    ONLY_ENABLE_ON_SCHIP = 0x22


# ── GFH_COMMON_HEADER: 8 bytes ──────────────────────────────────────────────
#   magic[3]  version:u8  size:u16  type:u16
# Parsers receive the bytes AFTER this 8-byte header (the body only).

# ── GFH_FILE_INFO body (after 8-byte header) ────────────────────────────────
#   name[12]  unused:u32  file_type:u16  flash_type:u8  sig_type:u8
#   load_addr:u32  total_size:u32  max_size:u32  hdr_size:u32
#   sig_size:u32  jump_offset:u32  processed:u32
FILE_INFO_FMT  = '<12sIHBBIIIIIII'
FILE_INFO_SIZE = struct.calcsize(FILE_INFO_FMT)   # 48 bytes

# ── GFH_BL_INFO body ─────────────────────────────────────────────────────────
#   attr:u32     bit 0 = loaded by BROM
BL_INFO_FMT  = '<I'
BL_INFO_SIZE = 4

# ── GFH_BROM_CFG body ────────────────────────────────────────────────────────
#   cfg_bits:u32  auto_detect_ms:u32  unused[0x48]
#   kcol0_ms:u32  flag_ms:u32  pad:u32
BROM_CFG_FMT  = '<II72xIII'
BROM_CFG_SIZE = struct.calcsize(BROM_CFG_FMT)   # 4+4+72+4+4+4 = 92 bytes

BROM_CFG_AUTO_DETECT_TIMEOUT_EN = 0x0002
BROM_CFG_AUTO_DETECT_DIS        = 0x0010
BROM_CFG_KCOL0_TIMEOUT_EN       = 0x0080
BROM_CFG_FLAG_TIMEOUT_EN        = 0x0100

# ── GFH_ANTI_CLONE body ──────────────────────────────────────────────────────
#   ac_b2k:u8  ac_b2c:u8  pad:u16  ac_offset:u32  ac_len:u32
ANTI_CLONE_FMT  = '<BBxHII'   # note: pad is 2 bytes (u16), skip with x+H trick
#  Correct: BBHxx → no, struct: BB 2pad II  → '<BB2xII'
ANTI_CLONE_FMT  = '<BB2xII'
ANTI_CLONE_SIZE = struct.calcsize(ANTI_CLONE_FMT)   # 1+1+2+4+4 = 12 bytes

# ── GFH_BROM_SEC_CFG body ────────────────────────────────────────────────────
#   cfg_bits:u32  customer_name[0x20]  pad:u32
BROM_SEC_FMT  = '<I32sI'
BROM_SEC_SIZE = struct.calcsize(BROM_SEC_FMT)   # 4+32+4 = 40 bytes

BROM_SEC_JTAG_EN = 0x01
BROM_SEC_UART_EN = 0x02


@dataclass
class StorageDeviceInfo:
    device_name:    str
    format_version: int
    sector_size:    int


@dataclass
class BootRegionInfo:
    structure_version: int
    boot_start:        int
    application_start: int


@dataclass
class LoaderDescriptor:
    validation_magic: bytes
    storage_id:       int
    component_type:   int
    start_position:   int
    end_boundary:     int
    flags:            int


@dataclass
class BootHeader:
    storage: StorageDeviceInfo
    regions: BootRegionInfo
    loaders: List[LoaderDescriptor]


@dataclass
class GfhBlockHeader:
    signature:    bytes
    revision:     int
    block_length: int
    block_type:   int


@dataclass
class FileDescriptor:
    filename:         str
    file_type:        int
    flash_type:       int
    sig_type:         int
    load_addr:        int
    total_size:       int
    max_size:         int
    hdr_size:         int
    sig_size:         int
    jump_offset:      int
    processed:        int


@dataclass
class BlInfo:
    load_by_bootrom: bool
    raw_attr:        int


@dataclass
class BromCfg:
    cfg_bits:         int
    auto_detect_ms:   int
    kcol0_ms:         int
    flag_ms:          int
    auto_detect_en:   bool
    auto_detect_dis:  bool
    kcol0_timeout_en: bool
    flag_timeout_en:  bool


@dataclass
class AntiClone:
    ac_b2k:    int
    ac_b2c:    int
    ac_offset: int
    ac_len:    int


@dataclass
class BromSecCfg:
    cfg_bits:      int
    customer_name: str
    jtag_enabled:  bool
    uart_enabled:  bool


@dataclass
class EmiEntry:
    emi_cona_val:        int
    dramc_drvctl0_val:   int
    dramc_drvctl1_val:   int
    dramc_actim_val:     int
    dramc_gddr3ctl1_val: int
    dramc_conf1_val:     int
    dramc_ddr2ctl_val:   int
    dramc_test2_3_val:   int
    dramc_conf2_val:     int
    dramc_pd_ctrl_val:   int
    dramc_padctl3_val:   int
    dramc_dqodly_val:    int
    dramc_addr_out_dly:  int
    dramc_dqs_dly:       int
    dramc_actim1_val:    int
    dramc_ckdly_val:     int
    id_info:             bytes


@dataclass
class EmiSettings:
    bloader_version: int
    entries:         List[EmiEntry]


@dataclass
class SecuritySettings:
    version:              int
    usb_download_mode:    int
    usb_download_status:  str
    secure_activation:    int
    secure_boot_status:   str
    modem_verification:   int
    secure_data_storage:  int
    anti_clone_enabled:   int
    legacy_aes:           int
    secure_rom_anti_clone: int
    sml_key_check:        int


@dataclass
class CryptographicMaterial:
    key_version:      int
    image_public_key: bytes
    image_exponent:   bytes
    sml_aes_key:      bytes
    random_seed:      bytes
    sml_public_key:   bytes
    sml_exponent:     bytes


@dataclass
class SystemFirmwareInfo:
    info_version:           int
    platform_identifier:    str
    project_identifier:     str
    secure_rom_exists:      int
    secure_rom_start:       int
    secure_rom_size:        int
    clone_protection_start: int
    clone_protection_size:  int
    security_config_start:  int
    security_config_size:   int
    security:               Optional[SecuritySettings] = None
    trusted_boot_parts:     Optional[List[str]] = None
    crypto_keys:            Optional[CryptographicMaterial] = None


@dataclass
class GfhPayload:
    header:    GfhBlockHeader
    data:      Any
    raw_bytes: bytes


@dataclass
class PreloaderAnalysis:
    raw_data:           bytes
    boot_structure:     Optional[BootHeader]
    gfh_start_offset:   int
    main_descriptor:    FileDescriptor
    bl_info:            Optional[BlInfo]
    brom_cfg:           Optional[BromCfg]
    anti_clone:         Optional[AntiClone]
    brom_sec_cfg:       Optional[BromSecCfg]
    emi_settings:       Optional[EmiSettings]
    all_sections:       List[GfhPayload]
    extracted_code:     bytes
    attached_signature: bytes
    system_info:        Optional[SystemFirmwareInfo]

    @property
    def md5(self) -> str:
        return hashlib.md5(self.raw_data).hexdigest()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw_data).hexdigest()

    @property
    def checksum(self) -> str:
        return self.md5


class ParserError(Exception):
    pass

class ValidationError(ParserError):
    pass

class StructureNotFoundError(ParserError):
    pass


def extract_string(buf: bytes) -> str:
    raw = buf.split(b'\x00', 1)[0]
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError:
        return raw.decode('latin-1', errors='replace')


def get_enum_name(cls, value: int) -> str:
    try:
        return cls(value).name
    except ValueError:
        return f'0x{value:04x}'


def sec_status_name(value: int) -> str:
    try:
        return SecStatus(value).name
    except ValueError:
        return f'0x{value:02x}'


_SECTION_PARSERS: Dict = {}


# ── individual section parsers ────────────────────────────────────────────────
# Each receives (body_bytes, gfh_revision) — body only, header already stripped.

def parse_file_descriptor(body: bytes, ver: int) -> Optional[FileDescriptor]:
    if len(body) < FILE_INFO_SIZE:
        return None
    try:
        (name_raw, _unused, file_type, flash_type, sig_type,
         load_addr, total_size, max_size, hdr_size,
         sig_size, jump_offset, processed) = struct.unpack_from(FILE_INFO_FMT, body)
        return FileDescriptor(
            filename    = extract_string(name_raw),
            file_type   = file_type,
            flash_type  = flash_type,
            sig_type    = sig_type,
            load_addr   = load_addr,
            total_size  = total_size,
            max_size    = max_size,
            hdr_size    = hdr_size,
            sig_size    = sig_size,
            jump_offset = jump_offset,
            processed   = processed,
        )
    except struct.error:
        return None


def parse_bl_info(body: bytes, ver: int) -> Optional[BlInfo]:
    if len(body) < BL_INFO_SIZE:
        return None
    attr = struct.unpack_from('<I', body)[0]
    return BlInfo(
        load_by_bootrom = bool(attr & 0x01),
        raw_attr        = attr,
    )


def parse_brom_cfg(body: bytes, ver: int) -> Optional[BromCfg]:
    if len(body) < BROM_CFG_SIZE:
        return None
    try:
        cfg_bits, auto_ms, kcol0_ms, flag_ms, _pad = \
            struct.unpack_from(BROM_CFG_FMT, body)
        return BromCfg(
            cfg_bits         = cfg_bits,
            auto_detect_ms   = auto_ms,
            kcol0_ms         = kcol0_ms,
            flag_ms          = flag_ms,
            auto_detect_en   = bool(cfg_bits & BROM_CFG_AUTO_DETECT_TIMEOUT_EN),
            auto_detect_dis  = bool(cfg_bits & BROM_CFG_AUTO_DETECT_DIS),
            kcol0_timeout_en = bool(cfg_bits & BROM_CFG_KCOL0_TIMEOUT_EN),
            flag_timeout_en  = bool(cfg_bits & BROM_CFG_FLAG_TIMEOUT_EN),
        )
    except struct.error:
        return None


def parse_anti_clone(body: bytes, ver: int) -> Optional[AntiClone]:
    if len(body) < ANTI_CLONE_SIZE:
        return None
    try:
        b2k, b2c, ac_offset, ac_len = struct.unpack_from(ANTI_CLONE_FMT, body)
        return AntiClone(ac_b2k=b2k, ac_b2c=b2c, ac_offset=ac_offset, ac_len=ac_len)
    except struct.error:
        return None


def parse_brom_sec_cfg(body: bytes, ver: int) -> Optional[BromSecCfg]:
    if len(body) < BROM_SEC_SIZE:
        return None
    try:
        cfg_bits, customer_raw, _pad = struct.unpack_from(BROM_SEC_FMT, body)
        return BromSecCfg(
            cfg_bits      = cfg_bits,
            customer_name = extract_string(customer_raw),
            jtag_enabled  = bool(cfg_bits & BROM_SEC_JTAG_EN),
            uart_enabled  = bool(cfg_bits & BROM_SEC_UART_EN),
        )
    except struct.error:
        return None


EMI_ENTRY_FMT  = '<' + 'I' * 16 + '4s'
EMI_ENTRY_SIZE = struct.calcsize(EMI_ENTRY_FMT)


def parse_emi_list(body: bytes, ver: int) -> Optional[EmiSettings]:
    if len(body) < 4:
        return None
    try:
        bloader_version = 0
        bl_idx = body.find(MTK_BLOADER_INFO)
        if bl_idx != -1:
            vs = bl_idx + len(MTK_BLOADER_INFO)
            vb = body[vs:vs + 2].rstrip(b'\x00')
            try:
                bloader_version = int(vb)
            except ValueError:
                pass

        bin_idx = body.find(MTK_BIN_MARKER)
        emi_data = body[bin_idx + 0x0C:] if bin_idx != -1 else body

        if len(emi_data) < 4:
            return EmiSettings(bloader_version=bloader_version, entries=[])

        dram_size = struct.unpack_from('<I', emi_data, len(emi_data) - 4)[0]
        if dram_size == 0 or dram_size > len(emi_data):
            if len(emi_data) >= 0x800 + 4:
                emi_data  = emi_data[:-0x800]
                dram_size = struct.unpack_from('<I', emi_data, len(emi_data) - 4)[0]

        if dram_size == 0 or dram_size > len(emi_data):
            return EmiSettings(bloader_version=bloader_version, entries=[])

        block   = emi_data[len(emi_data) - dram_size - 4: len(emi_data) - 4]
        entries = []
        pos     = 0
        while pos + EMI_ENTRY_SIZE <= len(block):
            f = struct.unpack_from(EMI_ENTRY_FMT, block, pos)
            entries.append(EmiEntry(
                emi_cona_val        = f[0],
                dramc_drvctl0_val   = f[1],
                dramc_drvctl1_val   = f[2],
                dramc_actim_val     = f[3],
                dramc_gddr3ctl1_val = f[4],
                dramc_conf1_val     = f[5],
                dramc_ddr2ctl_val   = f[6],
                dramc_test2_3_val   = f[7],
                dramc_conf2_val     = f[8],
                dramc_pd_ctrl_val   = f[9],
                dramc_padctl3_val   = f[10],
                dramc_dqodly_val    = f[11],
                dramc_addr_out_dly  = f[12],
                dramc_dqs_dly       = f[13],
                dramc_actim1_val    = f[14],
                dramc_ckdly_val     = f[15],
                id_info             = f[16],
            ))
            pos += EMI_ENTRY_SIZE

        return EmiSettings(bloader_version=bloader_version, entries=entries)
    except Exception:
        return None


def parse_key_material(body: bytes, ver: int) -> Optional[Dict[str, bytes]]:
    if len(body) < 524:
        return None
    kd = body[:524]
    return {'key_data': kd, 'hash': hashlib.sha256(kd).digest()}


def _build_section_parsers() -> Dict:
    return {
        GfhSectionType.FILE_DESCRIPTOR:  parse_file_descriptor,
        GfhSectionType.BOOTLOADER_INFO:  parse_bl_info,
        GfhSectionType.ROM_CONFIG:       parse_brom_cfg,
        GfhSectionType.CLONE_PROTECTION: parse_anti_clone,
        GfhSectionType.ROM_SECURITY:     parse_brom_sec_cfg,
        GfhSectionType.EMI_LIST:         parse_emi_list,
        GfhSectionType.BOOT_KEY:         parse_key_material,
    }


# ── AND_ROMINFO / AND_SECCTRL (inside payload code, not GFH sections) ─────────

def extract_security_settings(data: bytes, pos: int) -> Optional[SecuritySettings]:
    if pos + 48 > len(data):
        return None
    try:
        (magic, ver, usb_mode, boot_mode, modem, sds,
         ac, aes_leg, secro_ac, sml_ac, _) = \
            struct.unpack_from('<16sIIIIIBBBB12s', data, pos)
        if not magic.startswith(MagicTokens.ANDROID_SECURITY_CTRL):
            return None
        return SecuritySettings(
            version              = ver,
            usb_download_mode    = usb_mode,
            usb_download_status  = sec_status_name(usb_mode),
            secure_activation    = boot_mode,
            secure_boot_status   = sec_status_name(boot_mode),
            modem_verification   = modem,
            secure_data_storage  = sds,
            anti_clone_enabled   = ac,
            legacy_aes           = aes_leg,
            secure_rom_anti_clone = secro_ac,
            sml_key_check        = sml_ac,
        )
    except struct.error:
        return None


def extract_boot_components(data: bytes, pos: int) -> List[str]:
    if pos + 90 > len(data):
        return []
    try:
        parts = struct.unpack_from('<' + '10s' * 9, data, pos)
        return [extract_string(p).strip() for p in parts if extract_string(p).strip()]
    except struct.error:
        return []


def extract_crypto_keys(data: bytes, pos: int) -> Optional[CryptographicMaterial]:
    if pos + 340 > len(data):
        return None
    try:
        (magic, ver, img_n, img_e, aes_key, seed, sml_n, sml_e) = \
            struct.unpack_from('<16sI256s5s32s16s256s5s', data, pos)
        if not magic.startswith(MagicTokens.ANDROID_SECURITY_KEY):
            return None
        return CryptographicMaterial(
            key_version      = ver,
            image_public_key = img_n,
            image_exponent   = extract_string(img_e).encode(),
            sml_aes_key      = aes_key,
            random_seed      = extract_string(seed).encode(),
            sml_public_key   = sml_n,
            sml_exponent     = extract_string(sml_e).encode(),
        )
    except struct.error:
        return None


def parse_system_information(content: bytes) -> Optional[SystemFirmwareInfo]:
    magic    = MagicTokens.ANDROID_ROM_INFO
    end      = len(content)
    start    = max(0, end - 65536)

    pos = content.find(magic, start, end)
    if pos == -1:
        pos = content.find(magic, 0, min(start, 65536))
    if pos == -1 or pos + 128 > len(content):
        return None

    try:
        (magic_raw, ver, plat_raw, proj_raw, ro_exists,
         ro_start, ro_len, ac_start, ac_len, cfg_start,
         cfg_len, _) = struct.unpack_from('<16sI16s16sIIIIIII128s', content, pos)

        if not magic_raw.startswith(MagicTokens.ANDROID_ROM_INFO):
            return None

        sysinfo = SystemFirmwareInfo(
            info_version           = ver,
            platform_identifier    = extract_string(plat_raw),
            project_identifier     = extract_string(proj_raw),
            secure_rom_exists      = ro_exists,
            secure_rom_start       = ro_start,
            secure_rom_size        = ro_len,
            clone_protection_start = ac_start,
            clone_protection_size  = ac_len,
            security_config_start  = cfg_start,
            security_config_size   = cfg_len,
        )

        sec_pos = pos + 128
        sysinfo.security = extract_security_settings(content, sec_pos)

        if sysinfo.security:
            comp_pos = sec_pos + 48 + 18
            sysinfo.trusted_boot_parts = extract_boot_components(content, comp_pos)
            keys_pos = comp_pos + 90
            sysinfo.crypto_keys = extract_crypto_keys(content, keys_pos)

        return sysinfo
    except struct.error:
        return None


# ── GFH block walking ─────────────────────────────────────────────────────────

def parse_device_config(data: bytes) -> Optional[BootHeader]:
    if len(data) < 2048:
        return None
    dev_magic = data[:12]
    if dev_magic not in MagicTokens.BOOT_DEVICES:
        return None

    device_name         = MagicTokens.BOOT_DEVICES[dev_magic]
    version, block_size = struct.unpack_from('<II', data, 12)
    if block_size not in (512, 2048, 4096):
        return None

    brlyt = 512
    if data[brlyt:brlyt + 8] != MagicTokens.BRLYT_IDENTIFIER:
        return None

    brlyt_ver, boot_addr, app_addr = struct.unpack_from('<III', data, brlyt + 8)
    descriptors = []
    for i in range(8):
        off = brlyt + 20 + i * 20
        if off + 20 > len(data):
            break
        marker, sid, ctype, spos, epos, flags = struct.unpack_from('<4sHHIII', data, off)
        if marker == MagicTokens.BLOCK_EXIST_MARKER:
            descriptors.append(LoaderDescriptor(marker, sid, ctype, spos, epos, flags))

    return BootHeader(
        StorageDeviceInfo(device_name, version, block_size),
        BootRegionInfo(brlyt_ver, boot_addr, app_addr),
        descriptors,
    )


def locate_gfh_block(data: bytes) -> int:
    if len(data) >= 2048 and data[:12] in MagicTokens.BOOT_DEVICES:
        if len(data) > 528 and data[512:520] == MagicTokens.BRLYT_IDENTIFIER:
            hdr_size = struct.unpack_from('<I', data, 528)[0]
            if hdr_size > MAX_GFH_HDR_SIZE:
                raise ValidationError(f"Implausible GFH header size: 0x{hdr_size:08x}")
            if hdr_size + 3 <= len(data) and data[hdr_size:hdr_size + 3] == MagicTokens.GFH_SIGNATURE:
                return hdr_size
        if len(data) > 2051 and data[2048:2051] == MagicTokens.GFH_SIGNATURE:
            return 2048

    if data[:3] == MagicTokens.GFH_SIGNATURE:
        return 0

    target = MagicTokens.GFH_SIGNATURE_DWORD.to_bytes(4, 'little')
    off    = data.find(target, 0, min(len(data) - 3, 65536))
    if off != -1:
        return off

    raise StructureNotFoundError("Unable to locate GFH block")


def parse_gfh_header(data: bytes, pos: int) -> Optional[GfhBlockHeader]:
    if pos + 8 > len(data):
        return None
    magic, ver, length, btype = struct.unpack_from('<3sBHH', data, pos)
    if magic != MagicTokens.GFH_SIGNATURE or length < 8:
        return None
    return GfhBlockHeader(magic, ver, length, btype)


def parse_gfh_sections(
    data: bytes,
    start: int,
    end: Optional[int] = None,
) -> Tuple[Optional[FileDescriptor], List[GfhPayload]]:
    global _SECTION_PARSERS
    if not _SECTION_PARSERS:
        _SECTION_PARSERS = _build_section_parsers()

    main_desc = None
    sections  = []
    limit     = end if end is not None else len(data)
    pos       = start

    while pos + 8 <= limit:
        hdr = parse_gfh_header(data, pos)
        if not hdr:
            break
        if pos + hdr.block_length > len(data):
            break

        body_start = pos + 8
        body_end   = pos + hdr.block_length
        body       = data[body_start:body_end]

        try:
            stype  = GfhSectionType(hdr.block_type)
            parser = _SECTION_PARSERS.get(stype)
            parsed = parser(body, hdr.revision) if parser else body
        except ValueError:
            stype  = None
            parsed = body

        if stype == GfhSectionType.FILE_DESCRIPTOR and isinstance(parsed, FileDescriptor):
            main_desc = parsed

        sections.append(GfhPayload(hdr, parsed, data[pos:pos + hdr.block_length]))
        pos += hdr.block_length

    return main_desc, sections


def analyze_preloader(binary_data: bytes) -> PreloaderAnalysis:
    if len(binary_data) < 2056:
        raise ValidationError(f"Binary too small: {len(binary_data)} bytes")

    boot_hdr          = parse_device_config(binary_data)
    gfh_offset        = locate_gfh_block(binary_data)
    main_desc, sects  = parse_gfh_sections(binary_data, gfh_offset)

    if main_desc is None:
        raise StructureNotFoundError("Missing FILE_INFO section")
    if main_desc.file_type not in VALID_PAYLOAD_TYPES:
        raise ValidationError(f"Unexpected file_type: 0x{main_desc.file_type:04x}")

    hdr_end = gfh_offset + main_desc.hdr_size
    if hdr_end > len(binary_data):
        raise ValidationError("Header extends beyond file")

    bl_info_obj   = None
    brom_cfg_obj  = None
    anti_clone_obj = None
    sec_cfg_obj   = None
    emi_obj       = None

    for sec in sects:
        try:
            t = GfhSectionType(sec.header.block_type)
        except ValueError:
            continue
        if   t == GfhSectionType.BOOTLOADER_INFO  and isinstance(sec.data, BlInfo):
            bl_info_obj    = sec.data
        elif t == GfhSectionType.ROM_CONFIG        and isinstance(sec.data, BromCfg):
            brom_cfg_obj   = sec.data
        elif t == GfhSectionType.CLONE_PROTECTION  and isinstance(sec.data, AntiClone):
            anti_clone_obj = sec.data
        elif t == GfhSectionType.ROM_SECURITY      and isinstance(sec.data, BromSecCfg):
            sec_cfg_obj    = sec.data
        elif t == GfhSectionType.EMI_LIST          and isinstance(sec.data, EmiSettings):
            emi_obj        = sec.data

    payload_start   = gfh_offset + main_desc.hdr_size
    payload_end     = gfh_offset + main_desc.total_size - main_desc.sig_size
    sig_start       = payload_end
    sig_end         = gfh_offset + main_desc.total_size

    if payload_end > len(binary_data) or sig_end > len(binary_data):
        raise ValidationError("File appears truncated")

    code       = binary_data[payload_start:payload_end]
    sig        = binary_data[sig_start:sig_end]

    if emi_obj is None:
        emi_obj = parse_emi_list(code, 0)

    sys_info = parse_system_information(code)

    return PreloaderAnalysis(
        raw_data           = binary_data,
        boot_structure     = boot_hdr,
        gfh_start_offset   = gfh_offset,
        main_descriptor    = main_desc,
        bl_info            = bl_info_obj,
        brom_cfg           = brom_cfg_obj,
        anti_clone         = anti_clone_obj,
        brom_sec_cfg       = sec_cfg_obj,
        emi_settings       = emi_obj,
        all_sections       = sects,
        extracted_code     = code,
        attached_signature = sig,
        system_info        = sys_info,
    )


# ── reporting ─────────────────────────────────────────────────────────────────

def generate_report(analysis: PreloaderAnalysis, verbose: bool = False) -> str:
    L = []
    L.append("=" * 70)
    L.append("MediaTek Preloader Analysis Report")
    L.append("=" * 70)

    L.append("\n[File]")
    L.append(f"  MD5:    {analysis.md5}")
    L.append(f"  SHA256: {analysis.sha256}")
    L.append(f"  Size:   {len(analysis.raw_data):,} bytes")
    L.append(f"  GFH at: 0x{analysis.gfh_start_offset:08x}")

    d = analysis.main_descriptor
    L.append("\n[GFH_FILE_INFO]")
    L.append(f"  Name:        {d.filename}")
    L.append(f"  File type:   {get_enum_name(PayloadType, d.file_type)} (0x{d.file_type:04x})")
    L.append(f"  Flash type:  {get_enum_name(FlashType,   d.flash_type)} (0x{d.flash_type:02x})")
    L.append(f"  Sig type:    {get_enum_name(SigType,     d.sig_type)}  (0x{d.sig_type:02x})")
    L.append(f"  Load addr:   0x{d.load_addr:08x}")
    L.append(f"  Total size:  {d.total_size:,} bytes")
    L.append(f"  Max size:    {d.max_size:,} bytes")
    L.append(f"  Header size: {d.hdr_size} bytes")
    L.append(f"  Sig size:    {d.sig_size} bytes")
    L.append(f"  Jump offset: 0x{d.jump_offset:08x}  →  entry: 0x{d.load_addr + d.jump_offset:08x}")
    L.append(f"  Processed:   {d.processed}")

    if analysis.bl_info:
        bl = analysis.bl_info
        L.append("\n[GFH_BL_INFO]")
        L.append(f"  Load by BROM: {bl.load_by_bootrom}")
        L.append(f"  attr raw:     0x{bl.raw_attr:08x}")

    if analysis.brom_cfg:
        c = analysis.brom_cfg
        L.append("\n[GFH_BROM_CFG]")
        L.append(f"  cfg_bits:          0x{c.cfg_bits:08x}")
        L.append(f"  auto-detect en:    {c.auto_detect_en}")
        L.append(f"  auto-detect dis:   {c.auto_detect_dis}")
        L.append(f"  KCOL0 timeout en:  {c.kcol0_timeout_en}")
        L.append(f"  flag timeout en:   {c.flag_timeout_en}")
        L.append(f"  auto-detect ms:    {c.auto_detect_ms}")
        L.append(f"  KCOL0 ms:          {c.kcol0_ms}")
        L.append(f"  flag ms:           {c.flag_ms}")

    if analysis.anti_clone:
        ac = analysis.anti_clone
        L.append("\n[GFH_ANTI_CLONE]")
        L.append(f"  ac_b2k:   0x{ac.ac_b2k:02x}")
        L.append(f"  ac_b2c:   0x{ac.ac_b2c:02x}")
        L.append(f"  offset:   0x{ac.ac_offset:08x}")
        L.append(f"  length:   {ac.ac_len} bytes")

    if analysis.brom_sec_cfg:
        s = analysis.brom_sec_cfg
        L.append("\n[GFH_BROM_SEC_CFG]")
        L.append(f"  cfg_bits:      0x{s.cfg_bits:08x}")
        L.append(f"  JTAG enabled:  {s.jtag_enabled}")
        L.append(f"  UART enabled:  {s.uart_enabled}")
        L.append(f"  Customer name: {s.customer_name!r}")

    if analysis.emi_settings:
        emi = analysis.emi_settings
        L.append("\n[EMI_SETTINGS]")
        L.append(f"  BLOADER version: {emi.bloader_version}")
        L.append(f"  Entry count:     {len(emi.entries)}")
        for i, e in enumerate(emi.entries):
            L.append(f"\n  [Entry {i}]  id={e.id_info.hex()}")
            L.append(f"    EMI_CONA_VAL:        0x{e.emi_cona_val:08x}")
            L.append(f"    DRAMC_DRVCTL0_VAL:   0x{e.dramc_drvctl0_val:08x}")
            L.append(f"    DRAMC_DRVCTL1_VAL:   0x{e.dramc_drvctl1_val:08x}")
            L.append(f"    DRAMC_ACTIM_VAL:     0x{e.dramc_actim_val:08x}")
            L.append(f"    DRAMC_GDDR3CTL1_VAL: 0x{e.dramc_gddr3ctl1_val:08x}")
            L.append(f"    DRAMC_CONF1_VAL:     0x{e.dramc_conf1_val:08x}")
            L.append(f"    DRAMC_DDR2CTL_VAL:   0x{e.dramc_ddr2ctl_val:08x}")
            L.append(f"    DRAMC_TEST2_3_VAL:   0x{e.dramc_test2_3_val:08x}")
            L.append(f"    DRAMC_CONF2_VAL:     0x{e.dramc_conf2_val:08x}")
            L.append(f"    DRAMC_PD_CTRL_VAL:   0x{e.dramc_pd_ctrl_val:08x}")
            L.append(f"    DRAMC_PADCTL3_VAL:   0x{e.dramc_padctl3_val:08x}")
            L.append(f"    DRAMC_DQODLY_VAL:    0x{e.dramc_dqodly_val:08x}")
            L.append(f"    DRAMC_ADDR_OUT_DLY:  0x{e.dramc_addr_out_dly:08x}")
            L.append(f"    DRAMC_DQS_DLY:       0x{e.dramc_dqs_dly:08x}")
            L.append(f"    DRAMC_ACTIM1_VAL:    0x{e.dramc_actim1_val:08x}")
            L.append(f"    DRAMC_CKDLY_VAL:     0x{e.dramc_ckdly_val:08x}")

    if analysis.boot_structure:
        b = analysis.boot_structure
        L.append("\n[BRLYT]")
        L.append(f"  Device:  {b.storage.device_name}")
        L.append(f"  Version: {b.storage.format_version}")
        L.append(f"  Sector:  {b.storage.sector_size} bytes")
        L.append(f"  Loaders: {len(b.loaders)}")
        if verbose:
            for i, ld in enumerate(b.loaders):
                L.append(f"    [{i}] type=0x{ld.component_type:04x}  "
                         f"start=0x{ld.start_position:08x}  end=0x{ld.end_boundary:08x}")

    if analysis.system_info:
        si = analysis.system_info
        L.append("\n[AND_ROMINFO]")
        L.append(f"  Platform:    {si.platform_identifier}")
        L.append(f"  Project:     {si.project_identifier}")
        L.append(f"  ROM version: {si.info_version}")
        L.append(f"  SecRO exist: {bool(si.secure_rom_exists)}")

        if si.security:
            sec = si.security
            L.append("\n[AND_SECCTRL]")
            L.append(f"  Version:      {sec.version}")
            L.append(f"  USB download: {sec.usb_download_status} (0x{sec.usb_download_mode:02x})")
            L.append(f"  Secure boot:  {sec.secure_boot_status} (0x{sec.secure_activation:02x})")
            L.append(f"  Modem auth:   {'yes' if sec.modem_verification else 'no'}")
            L.append(f"  Secure data:  {'yes' if sec.secure_data_storage else 'no'}")
            L.append(f"  Anti-clone:   {'yes' if sec.anti_clone_enabled else 'no'}")
            L.append(f"  AES legacy:   {'yes' if sec.legacy_aes else 'no'}")
            L.append(f"  SecRO AC:     {'yes' if sec.secure_rom_anti_clone else 'no'}")
            L.append(f"  SML key chk:  {'yes' if sec.sml_key_check else 'no'}")

        if si.trusted_boot_parts:
            L.append("\n[AND_SECBOOT_CHECK_PART]")
            for p in si.trusted_boot_parts:
                L.append(f"  - {p}")

    L.append("\n[Signature]")
    L.append(f"  Present: {'yes' if analysis.attached_signature else 'no'}")
    if analysis.attached_signature and verbose:
        L.append(f"  First 64B: {analysis.attached_signature[:64].hex()}")

    L.append("\n[GFH sections]")
    for i, sec in enumerate(analysis.all_sections):
        tname = get_enum_name(GfhSectionType, sec.header.block_type)
        L.append(f"  [{i:2d}] {tname:<20s}  rev={sec.header.revision}  size={sec.header.block_length}")

    L.append("\n" + "=" * 70)
    return "\n".join(L)


def build_json_output(analysis: PreloaderAnalysis) -> Dict[str, Any]:
    d   = analysis.main_descriptor
    out: Dict[str, Any] = {
        'md5':    analysis.md5,
        'sha256': analysis.sha256,
        'size':   len(analysis.raw_data),
        'gfh_offset': analysis.gfh_start_offset,
        'gfh_file_info': {
            'name':        d.filename,
            'file_type':   d.file_type,
            'flash_type':  d.flash_type,
            'sig_type':    d.sig_type,
            'load_addr':   d.load_addr,
            'total_size':  d.total_size,
            'max_size':    d.max_size,
            'hdr_size':    d.hdr_size,
            'sig_size':    d.sig_size,
            'jump_offset': d.jump_offset,
            'entry_point': d.load_addr + d.jump_offset,
            'processed':   d.processed,
        },
        'signature_present': bool(analysis.attached_signature),
        'section_count':     len(analysis.all_sections),
    }

    if analysis.bl_info:
        bl = analysis.bl_info
        out['gfh_bl_info'] = {'load_by_bootrom': bl.load_by_bootrom, 'raw_attr': bl.raw_attr}

    if analysis.brom_cfg:
        c = analysis.brom_cfg
        out['gfh_brom_cfg'] = {
            'cfg_bits':        c.cfg_bits,
            'auto_detect_en':  c.auto_detect_en,
            'auto_detect_dis': c.auto_detect_dis,
            'kcol0_timeout_en': c.kcol0_timeout_en,
            'flag_timeout_en': c.flag_timeout_en,
            'auto_detect_ms':  c.auto_detect_ms,
            'kcol0_ms':        c.kcol0_ms,
            'flag_ms':         c.flag_ms,
        }

    if analysis.anti_clone:
        ac = analysis.anti_clone
        out['gfh_anti_clone'] = {
            'ac_b2k':   ac.ac_b2k,
            'ac_b2c':   ac.ac_b2c,
            'ac_offset': ac.ac_offset,
            'ac_len':   ac.ac_len,
        }

    if analysis.brom_sec_cfg:
        s = analysis.brom_sec_cfg
        out['gfh_brom_sec_cfg'] = {
            'cfg_bits':      s.cfg_bits,
            'jtag_enabled':  s.jtag_enabled,
            'uart_enabled':  s.uart_enabled,
            'customer_name': s.customer_name,
        }

    if analysis.emi_settings:
        emi = analysis.emi_settings
        out['emi_settings'] = {
            'bloader_version': emi.bloader_version,
            'entry_count':     len(emi.entries),
            'entries': [
                {
                    'id_info':              e.id_info.hex(),
                    'EMI_CONA_VAL':         e.emi_cona_val,
                    'DRAMC_DRVCTL0_VAL':    e.dramc_drvctl0_val,
                    'DRAMC_DRVCTL1_VAL':    e.dramc_drvctl1_val,
                    'DRAMC_ACTIM_VAL':      e.dramc_actim_val,
                    'DRAMC_GDDR3CTL1_VAL':  e.dramc_gddr3ctl1_val,
                    'DRAMC_CONF1_VAL':      e.dramc_conf1_val,
                    'DRAMC_DDR2CTL_VAL':    e.dramc_ddr2ctl_val,
                    'DRAMC_TEST2_3_VAL':    e.dramc_test2_3_val,
                    'DRAMC_CONF2_VAL':      e.dramc_conf2_val,
                    'DRAMC_PD_CTRL_VAL':    e.dramc_pd_ctrl_val,
                    'DRAMC_PADCTL3_VAL':    e.dramc_padctl3_val,
                    'DRAMC_DQODLY_VAL':     e.dramc_dqodly_val,
                    'DRAMC_ADDR_OUT_DLY':   e.dramc_addr_out_dly,
                    'DRAMC_DQS_DLY':        e.dramc_dqs_dly,
                    'DRAMC_ACTIM1_VAL':     e.dramc_actim1_val,
                    'DRAMC_CKDLY_VAL':      e.dramc_ckdly_val,
                }
                for e in emi.entries
            ],
        }

    if analysis.boot_structure:
        b = analysis.boot_structure
        out['brlyt'] = {
            'device':         b.storage.device_name,
            'format_version': b.storage.format_version,
            'sector_size':    b.storage.sector_size,
            'loaders': [
                {'index': i, 'component_type': l.component_type,
                 'start': l.start_position, 'end': l.end_boundary, 'flags': l.flags}
                for i, l in enumerate(b.loaders)
            ],
        }

    if analysis.system_info:
        si = analysis.system_info
        out['and_rominfo'] = {
            'platform':    si.platform_identifier,
            'project':     si.project_identifier,
            'rom_version': si.info_version,
            'secro_exists': bool(si.secure_rom_exists),
        }
        if si.security:
            sec = si.security
            out['and_secctrl'] = {
                'version':             sec.version,
                'usb_download_mode':   sec.usb_download_mode,
                'usb_download_status': sec.usb_download_status,
                'secure_activation':   sec.secure_activation,
                'secure_boot_status':  sec.secure_boot_status,
                'modem_auth':          bool(sec.modem_verification),
                'secure_data_storage': bool(sec.secure_data_storage),
                'anti_clone':          bool(sec.anti_clone_enabled),
                'aes_legacy':          bool(sec.legacy_aes),
                'secro_ac':            bool(sec.secure_rom_anti_clone),
                'sml_key_check':       bool(sec.sml_key_check),
            }
        if si.trusted_boot_parts:
            out['and_secboot_parts'] = si.trusted_boot_parts

    return out


def main():
    ap = argparse.ArgumentParser(description="MediaTek Preloader Analysis Tool")
    ap.add_argument('input_file')
    ap.add_argument('-v', '--verbose',   action='store_true')
    ap.add_argument('-o', '--output',    help='Save extracted payload')
    ap.add_argument('-s', '--signature', help='Save signature bytes')
    ap.add_argument('--json',            action='store_true')
    args = ap.parse_args()

    try:
        path = Path(args.input_file)
        if not path.exists():
            raise FileNotFoundError(f"Not found: {args.input_file}")
        if path.stat().st_size > MAX_FILE_SIZE:
            raise ValidationError("File exceeds 256 MB limit")

        data     = path.read_bytes()
        analysis = analyze_preloader(data)

        if args.json:
            import json
            print(json.dumps(build_json_output(analysis), indent=2))
        else:
            print(generate_report(analysis, args.verbose))

        if args.output:
            Path(args.output).write_bytes(analysis.extracted_code)
            print(f"[+] Payload → {args.output}")

        if args.signature and analysis.attached_signature:
            Path(args.signature).write_bytes(analysis.attached_signature)
            print(f"[+] Signature → {args.signature}")

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr); sys.exit(1)
    except (ParserError, ValidationError, StructureNotFoundError) as e:
        print(f"Parse error: {e}", file=sys.stderr); sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if '-v' in sys.argv or '--verbose' in sys.argv:
            import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
