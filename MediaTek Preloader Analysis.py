# MediaTek Boot Image Parser - Original Implementation

import hashlib
import struct
import sys
import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path


class MagicTokens:
    GFH_SIGNATURE = b'MMM'
    GFH_SIGNATURE_DWORD = 0x014D4D4D
    BRLYT_IDENTIFIER = b'BRLYT\x00\x00\x00'
    BLOCK_EXIST_MARKER = b'BBBB'
    ANDROID_ROM_INFO = b'AND_ROMINFO_v'
    ANDROID_SECURITY_CTRL = b'AND_SECCTRL_v'
    ANDROID_SECURITY_KEY = b'AND_SECRO_v'
    
    BOOT_DEVICES = {
        b'EMMC_BOOT\x00\x00\x00': 'EMMC_BOOT',
        b'SDMMC_BOOT\x00\x00': 'SDMMC_BOOT',
        b'SF_BOOT\x00\x00\x00\x00\x00': 'SF_BOOT'
    }


class GfhSectionType(Enum):
    FILE_DESCRIPTOR = 0x0000
    BOOTLOADER_INFO = 0x0001
    CLONE_PROTECTION = 0x0002
    BOOT_KEY = 0x0003
    CERTIFICATE = 0x0004
    AUTH_TOKEN = 0x0005
    ROM_CONFIG = 0x0007
    ROM_SECURITY = 0x0008
    ROOT_OF_TRUST = 0x000B
    EXPIRY_CHECK = 0x000C
    PARAMETERS = 0x000D
    CHIP_REVISION = 0x000E
    MODEM_CONFIG = 0x0010
    MAUI_KEY = 0x0202


class PayloadType(Enum):
    EMPTY = 0x0000
    ARM_CODE = 0x0001
    EXTENDED_ARM = 0x0002
    SECURITY_CERT = 0x0004
    AUTH_DATA = 0x0005
    EXEC_PARAMS = 0x0007
    TRUST_ANCHOR = 0x000A
    APPLICATION_PAYLOAD = 0x000B


class StorageType(Enum):
    UNKNOWN = 0
    NOR_FLASH = 1
    NAND_SEQUENTIAL = 2
    NAND_TABLE = 3
    NAND_DMA = 4
    EMMC_BOOT_AREA = 5
    EMMC_USER_AREA = 6
    SERIAL_FLASH = 7
    XBOOT = 8


class SignatureScheme(Enum):
    NONE = 0
    SHA2_256 = 1
    RSA_SINGLE = 2
    RSA_WITH_HASH = 3
    MULTIPLE_KEYS = 4
    CUSTOM = 5


@dataclass
class StorageDeviceInfo:
    device_name: str
    format_version: int
    sector_size: int


@dataclass
class BootRegionInfo:
    structure_version: int
    boot_start: int
    application_start: int


@dataclass
class LoaderDescriptor:
    validation_magic: bytes
    storage_id: int
    component_type: int
    start_position: int
    end_boundary: int
    flags: int


@dataclass
class BootHeader:
    storage: StorageDeviceInfo
    regions: BootRegionInfo
    loaders: List[LoaderDescriptor]


@dataclass
class GfhBlockHeader:
    signature: bytes
    revision: int
    block_length: int
    block_type: int


@dataclass
class FileDescriptor:
    filename: str
    payload_category: int
    target_storage: int
    security_level: int
    execution_address: int
    total_length: int
    maximum_length: int
    header_length: int
    signature_length: int
    entry_offset: int
    is_processed: int


@dataclass
class SecuritySettings:
    version: int
    usb_download_mode: int
    secure_activation: int
    modem_verification: int
    secure_data_storage: int
    anti_clone_enabled: int
    legacy_aes: int
    secure_rom_anti_clone: int
    sml_key_check: int


@dataclass
class CryptographicMaterial:
    key_version: int
    image_public_key: bytes
    image_exponent: bytes
    sml_aes_key: bytes
    random_seed: bytes
    sml_public_key: bytes
    sml_exponent: bytes


@dataclass
class SystemFirmwareInfo:
    info_version: int
    platform_identifier: str
    project_identifier: str
    secure_rom_exists: int
    secure_rom_start: int
    secure_rom_size: int
    clone_protection_start: int
    clone_protection_size: int
    security_config_start: int
    security_config_size: int
    security: Optional[SecuritySettings] = None
    trusted_boot_parts: List[str] = None
    crypto_keys: Optional[CryptographicMaterial] = None


@dataclass
class GfhPayload:
    header: GfhBlockHeader
    data: Any
    raw_bytes: bytes


@dataclass
class PreloaderAnalysis:
    raw_data: bytes
    boot_structure: Optional[BootHeader]
    gfh_start_offset: int
    main_descriptor: FileDescriptor
    all_sections: List[GfhPayload]
    extracted_code: bytes
    attached_signature: bytes
    system_info: Optional[SystemFirmwareInfo]
    
    @property
    def checksum(self) -> str:
        return hashlib.md5(self.raw_data).hexdigest()


class ParserError(Exception):
    pass


class ValidationError(ParserError):
    pass


class StructureNotFoundError(ParserError):
    pass


def extract_string(buffer: bytes) -> str:
    return buffer.split(b'\x00', 1)[0].decode('ascii', errors='replace')


def get_enum_name(enum_class, value: int) -> str:
    try:
        return enum_class(value).name
    except ValueError:
        return f'0x{value:04x}'


def parse_device_config(data: bytes) -> Optional[BootHeader]:
    if len(data) < 2048:
        return None
    
    device_magic = data[:12]
    if device_magic not in MagicTokens.BOOT_DEVICES:
        return None
    
    device_name = MagicTokens.BOOT_DEVICES[device_magic]
    version, block_size = struct.unpack_from('<II', data, 12)
    
    if block_size not in (512, 2048, 4096):
        return None
    
    storage_info = StorageDeviceInfo(device_name, version, block_size)
    
    brlyt_start = 512
    if data[brlyt_start:brlyt_start + 8] != MagicTokens.BRLYT_IDENTIFIER:
        return None
    
    brlyt_version, boot_addr, app_addr = struct.unpack_from(
        '<III', data, brlyt_start + 8
    )
    region_info = BootRegionInfo(brlyt_version, boot_addr, app_addr)
    
    descriptors = []
    desc_table_start = brlyt_start + 20
    
    for idx in range(8):
        offset = desc_table_start + idx * 20
        if offset + 20 > len(data):
            break
        
        marker, storage_id, comp_type, start_pos, end_pos, flags = \
            struct.unpack_from('<4sHHIII', data, offset)
        
        if marker == MagicTokens.BLOCK_EXIST_MARKER:
            descriptors.append(
                LoaderDescriptor(marker, storage_id, comp_type, 
                               start_pos, end_pos, flags)
            )
    
    return BootHeader(storage_info, region_info, descriptors)


def locate_gfh_block(data: bytes) -> int:
    if len(data) >= 2048 and data[:12] in MagicTokens.BOOT_DEVICES:
        if len(data) > 528 and data[512:520] == MagicTokens.BRLYT_IDENTIFIER:
            header_size = struct.unpack_from('<I', data, 528)[0]
            if header_size + 3 <= len(data) and \
               data[header_size:header_size + 3] == MagicTokens.GFH_SIGNATURE:
                return header_size
        
        if data[2048:2051] == MagicTokens.GFH_SIGNATURE:
            return 2048
    
    if data[:3] == MagicTokens.GFH_SIGNATURE:
        return 0
    
    search_limit = min(len(data), 65536)
    target_bytes = MagicTokens.GFH_SIGNATURE_DWORD.to_bytes(4, 'little')
    
    for offset in range(0, search_limit - 3, 4):
        if data[offset:offset + 4] == target_bytes:
            return offset
    
    raise StructureNotFoundError("Unable to locate GFH block")


def parse_gfh_header(data: bytes, position: int) -> Optional[GfhBlockHeader]:
    if position + 8 > len(data):
        return None
    
    magic, ver, length, block_type = struct.unpack_from('<3sBHH', data, position)
    
    if magic != MagicTokens.GFH_SIGNATURE or length < 8:
        return None
    
    return GfhBlockHeader(magic, ver, length, block_type)


def parse_file_descriptor(raw: bytes) -> Optional[FileDescriptor]:
    if len(raw) < 44:
        return None
    
    try:
        (name_raw, _, category, storage, security, exec_addr,
         total_len, max_len, header_len, sig_len, entry_off, processed) = \
            struct.unpack_from('<12sIHBBIIIIIII', raw)
        
        return FileDescriptor(
            filename=extract_string(name_raw),
            payload_category=category,
            target_storage=storage,
            security_level=security,
            execution_address=exec_addr,
            total_length=total_len,
            maximum_length=max_len,
            header_length=header_len,
            signature_length=sig_len,
            entry_offset=entry_off,
            is_processed=processed
        )
    except struct.error:
        return None


def parse_boot_flags(raw: bytes) -> Optional[bool]:
    if len(raw) < 4:
        return None
    flags = struct.unpack_from('<I', raw)[0]
    return bool(flags & 1)


def parse_rom_configuration(raw: bytes) -> Optional[Dict[str, Any]]:
    if len(raw) < 92:
        return None
    
    try:
        (flags, auto_timeout, _, _, _, _, _, _, arm64_magic, _, _, kcol0) = \
            struct.unpack_from('<II64sBBBBBBBBI', raw)
        
        return {
            'raw_flags': flags,
            'auto_detect_timeout': auto_timeout,
            'uart_disabled': bool(flags & 0x80),
            'usb_auto_detect_disabled': bool(flags & 0x10),
            'timeout_enabled': bool(flags & 0x02),
            'kcol0_enabled': bool(flags & 0x80),
            'flag_timeout_enabled': bool(flags & 0x100),
            'arm64_mode': bool(flags & 0x1000),
            'arm64_jump': arm64_magic,
            'kcol0_timeout': kcol0
        }
    except struct.error:
        return None


def parse_anti_clone_data(raw: bytes) -> Optional[Dict[str, int]]:
    if len(raw) < 12:
        return None
    
    try:
        b2k, b2c, offset, length = struct.unpack_from('<HHII', raw)
        return {'b2k': b2k, 'b2c': b2c, 'offset': offset, 'length': length}
    except struct.error:
        return None


def parse_security_configuration(raw: bytes) -> Optional[Dict[str, Any]]:
    if len(raw) < 44:
        return None
    
    try:
        flags, customer, perm_magic = struct.unpack_from('<I32sI', raw)
        
        return {
            'jtag_enabled': bool(flags & 1),
            'debug_enabled': bool(flags & 2),
            'customer_name': extract_string(customer),
            'permanently_locked': perm_magic == 0xC975E033
        }
    except struct.error:
        return None


def parse_key_material(raw: bytes) -> Optional[Dict[str, bytes]]:
    if len(raw) < 524:
        return None
    
    key_data = raw[:524]
    return {
        'key_data': key_data,
        'hash': hashlib.sha256(key_data).digest()
    }


def extract_security_settings(data: bytes, position: int) -> Optional[SecuritySettings]:
    if position + 48 > len(data):
        return None
    
    try:
        (magic, ver, usb_mode, boot_mode, modem_auth, sds_enable,
         ac_enable, aes_legacy, secro_ac, sml_ac, _) = \
            struct.unpack_from('<16sIIIIIBBBB12s', data, position)
        
        if not magic.startswith(MagicTokens.ANDROID_SECURITY_CTRL):
            return None
        
        return SecuritySettings(
            version=ver,
            usb_download_mode=usb_mode,
            secure_activation=boot_mode,
            modem_verification=modem_auth,
            secure_data_storage=sds_enable,
            anti_clone_enabled=ac_enable,
            legacy_aes=aes_legacy,
            secure_rom_anti_clone=secro_ac,
            sml_key_check=sml_ac
        )
    except struct.error:
        return None


def extract_boot_components(data: bytes, position: int) -> List[str]:
    if position + 90 > len(data):
        return []
    
    try:
        components = struct.unpack_from('<' + '10s' * 9, data, position)
        return [extract_string(c).strip() for c in components if extract_string(c).strip()]
    except struct.error:
        return []


def extract_crypto_keys(data: bytes, position: int) -> Optional[CryptographicMaterial]:
    if position + 340 > len(data):
        return None
    
    try:
        (magic, ver, img_n, img_e, aes_key, seed, sml_n, sml_e) = \
            struct.unpack_from('<16sI256s5s32s16s256s5s', data, position)
        
        if not magic.startswith(MagicTokens.ANDROID_SECURITY_KEY):
            return None
        
        return CryptographicMaterial(
            key_version=ver,
            image_public_key=img_n,
            image_exponent=extract_string(img_e).encode(),
            sml_aes_key=aes_key,
            random_seed=extract_string(seed).encode(),
            sml_public_key=sml_n,
            sml_exponent=extract_string(sml_e).encode()
        )
    except struct.error:
        return None


def parse_system_information(content: bytes) -> Optional[SystemFirmwareInfo]:
    search_start = max(0, len(content) - 65536)
    info_offset = None
    
    for offset in range(search_start, min(len(content), 65536), 4):
        if content[offset:offset + len(MagicTokens.ANDROID_ROM_INFO)] == MagicTokens.ANDROID_ROM_INFO:
            info_offset = offset
            break
    
    if info_offset is None or info_offset + 128 > len(content):
        return None
    
    try:
        (magic, ver, platform_raw, project_raw, ro_exists,
         ro_start, ro_len, ac_start, ac_len, cfg_start,
         cfg_len, _) = struct.unpack_from('<16sI16s16sIIIIIII128s', 
                                         content, info_offset)
        
        if not magic.startswith(MagicTokens.ANDROID_ROM_INFO):
            return None
        
        system_info = SystemFirmwareInfo(
            info_version=ver,
            platform_identifier=extract_string(platform_raw),
            project_identifier=extract_string(project_raw),
            secure_rom_exists=ro_exists,
            secure_rom_start=ro_start,
            secure_rom_size=ro_len,
            clone_protection_start=ac_start,
            clone_protection_size=ac_len,
            security_config_start=cfg_start,
            security_config_size=cfg_len
        )
        
        security_offset = info_offset + 128
        system_info.security = extract_security_settings(content, security_offset)
        
        if system_info.security:
            components_offset = security_offset + 48 + 18
            system_info.trusted_boot_parts = extract_boot_components(content, components_offset)
            
            keys_offset = components_offset + 90
            system_info.crypto_keys = extract_crypto_keys(content, keys_offset)
        
        return system_info
    except struct.error:
        return None


def parse_gfh_sections(data: bytes, start: int, end: Optional[int] = None) -> Tuple[Optional[FileDescriptor], List[GfhPayload]]:
    main_descriptor = None
    sections = []
    limit = end if end is not None else len(data)
    position = start
    
    section_parsers = {
        GfhSectionType.FILE_DESCRIPTOR: parse_file_descriptor,
        GfhSectionType.BOOTLOADER_INFO: parse_boot_flags,
        GfhSectionType.ROM_CONFIG: parse_rom_configuration,
        GfhSectionType.CLONE_PROTECTION: parse_anti_clone_data,
        GfhSectionType.ROM_SECURITY: parse_security_configuration,
        GfhSectionType.BOOT_KEY: parse_key_material
    }
    
    while position + 8 <= limit:
        header = parse_gfh_header(data, position)
        if not header:
            break
        
        if position + header.block_length > len(data):
            break
        
        payload_start = position + 8
        payload_end = position + header.block_length
        raw_payload = data[payload_start:payload_end]
        
        section_type = GfhSectionType(header.block_type)
        parser = section_parsers.get(section_type)
        
        if parser:
            parsed_data = parser(raw_payload)
        else:
            parsed_data = raw_payload
        
        if section_type == GfhSectionType.FILE_DESCRIPTOR and isinstance(parsed_data, FileDescriptor):
            main_descriptor = parsed_data
        
        sections.append(GfhPayload(header, parsed_data, data[position:position + header.block_length]))
        position += header.block_length
    
    return main_descriptor, sections


def analyze_preloader(binary_data: bytes) -> PreloaderAnalysis:
    if len(binary_data) < 2056:
        raise ValidationError(f"Binary too small: {len(binary_data)} bytes")
    
    boot_header = parse_device_config(binary_data)
    gfh_offset = locate_gfh_block(binary_data)
    
    main_desc, all_sections = parse_gfh_sections(binary_data, gfh_offset)
    
    if main_desc is None:
        raise StructureNotFoundError("Missing file descriptor section")
    
    if main_desc.payload_category not in (PayloadType.ARM_CODE.value,
                                          PayloadType.EXTENDED_ARM.value,
                                          PayloadType.APPLICATION_PAYLOAD.value):
        raise ValidationError(f"Invalid payload type: 0x{main_desc.payload_category:04x}")
    
    header_boundary = gfh_offset + main_desc.header_length
    if header_boundary > len(binary_data):
        raise ValidationError("Header extends beyond file")
    
    _, sections = parse_gfh_sections(binary_data, gfh_offset, header_boundary)
    
    payload_start = gfh_offset + main_desc.header_length
    payload_end = gfh_offset + main_desc.total_length - main_desc.signature_length
    signature_start = payload_end
    signature_end = gfh_offset + main_desc.total_length
    
    if payload_end > len(binary_data) or signature_end > len(binary_data):
        raise ValidationError("File appears truncated")
    
    extracted_code = binary_data[payload_start:payload_end]
    signature_data = binary_data[signature_start:signature_end]
    system_info = parse_system_information(extracted_code)
    
    return PreloaderAnalysis(
        raw_data=binary_data,
        boot_structure=boot_header,
        gfh_start_offset=gfh_offset,
        main_descriptor=main_desc,
        all_sections=sections,
        extracted_code=extracted_code,
        attached_signature=signature_data,
        system_info=system_info
    )


def generate_report(analysis: PreloaderAnalysis, verbose: bool = False) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("MediaTek Preloader Analysis Report")
    lines.append("=" * 70)
    
    lines.append(f"\n[File Information]")
    lines.append(f"  MD5 Checksum: {analysis.checksum}")
    lines.append(f"  Total Size: {len(analysis.raw_data):,} bytes")
    lines.append(f"  GFH Location: 0x{analysis.gfh_start_offset:04x}")
    
    lines.append(f"\n[Primary Descriptor]")
    desc = analysis.main_descriptor
    lines.append(f"  Name: {desc.filename}")
    lines.append(f"  Type: {get_enum_name(PayloadType, desc.payload_category)}")
    lines.append(f"  Storage: {get_enum_name(StorageType, desc.target_storage)}")
    lines.append(f"  Security: {get_enum_name(SignatureScheme, desc.security_level)}")
    lines.append(f"  Load Address: 0x{desc.execution_address:08x}")
    lines.append(f"  Total Length: {desc.total_length:,} bytes")
    lines.append(f"  Header Size: {desc.header_length} bytes")
    lines.append(f"  Signature Size: {desc.signature_length} bytes")
    
    if analysis.boot_structure:
        lines.append(f"\n[Boot Configuration]")
        boot = analysis.boot_structure
        lines.append(f"  Device: {boot.storage.device_name}")
        lines.append(f"  Format Version: {boot.storage.format_version}")
        lines.append(f"  Sector Size: {boot.storage.sector_size}")
        lines.append(f"  Boot Loaders: {len(boot.loaders)}")
        
        if verbose:
            for idx, loader in enumerate(boot.loaders):
                lines.append(f"    [{idx}] Type={loader.component_type}, "
                           f"Start=0x{loader.start_position:08x}")
    
    if analysis.system_info:
        info = analysis.system_info
        lines.append(f"\n[System Information]")
        lines.append(f"  Platform: {info.platform_identifier}")
        lines.append(f"  Project: {info.project_identifier}")
        lines.append(f"  ROM Version: {info.info_version}")
        
        if info.security:
            sec = info.security
            lines.append(f"\n[Security Configuration]")
            lines.append(f"  Secure Boot: {get_enum_name(SignatureScheme, sec.secure_activation)}")
            lines.append(f"  USB Download: {get_enum_name(SignatureScheme, sec.usb_download_mode)}")
            lines.append(f"  Modem Auth: {'Enabled' if sec.modem_verification else 'Disabled'}")
        
        if info.trusted_boot_parts:
            lines.append(f"\n[Trusted Components]")
            for part in info.trusted_boot_parts:
                lines.append(f"  - {part}")
    
    lines.append(f"\n[Signature Status]")
    lines.append(f"  Present: {'Yes' if analysis.attached_signature else 'No'}")
    if analysis.attached_signature and verbose:
        sig_hex = analysis.attached_signature[:64].hex()
        lines.append(f"  Data (first 64 bytes): {sig_hex}...")
    
    lines.append(f"\n[GFH Sections]")
    lines.append(f"  Total Count: {len(analysis.all_sections)}")
    if verbose:
        for idx, section in enumerate(analysis.all_sections):
            type_name = get_enum_name(GfhSectionType, section.header.block_type)
            lines.append(f"    [{idx}] {type_name} - {section.header.block_length} bytes")
    
    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="MediaTek Preloader Analysis Tool"
    )
    parser.add_argument('input_file', help='Path to preloader binary file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display detailed information')
    parser.add_argument('-o', '--output', help='Save extracted payload to file')
    parser.add_argument('-s', '--signature', help='Save signature to file')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    args = parser.parse_args()
    
    try:
        input_path = Path(args.input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {args.input_file}")
        
        with open(input_path, 'rb') as file_handle:
            binary_data = file_handle.read()
        
        analysis = analyze_preloader(binary_data)
        
        if args.json:
            import json
            output_data = {
                'md5': analysis.checksum,
                'size': len(analysis.raw_data),
                'gfh_offset': analysis.gfh_start_offset,
                'file_info': {
                    'name': analysis.main_descriptor.filename,
                    'type': analysis.main_descriptor.payload_category,
                    'type_name': get_enum_name(PayloadType, analysis.main_descriptor.payload_category),
                    'storage': analysis.main_descriptor.target_storage,
                    'load_address': analysis.main_descriptor.execution_address,
                    'total_size': analysis.main_descriptor.total_length
                }
            }
            if analysis.system_info:
                output_data['platform'] = analysis.system_info.platform_identifier
                output_data['project'] = analysis.system_info.project_identifier
            print(json.dumps(output_data, indent=2))
        else:
            report = generate_report(analysis, args.verbose)
            print(report)
        
        if args.output:
            with open(args.output, 'wb') as out_file:
                out_file.write(analysis.extracted_code)
            print(f"\n[+] Extracted payload saved to: {args.output}")
        
        if args.signature and analysis.attached_signature:
            with open(args.signature, 'wb') as sig_file:
                sig_file.write(analysis.attached_signature)
            print(f"[+] Signature saved to: {args.signature}")
    
    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    except (ParserError, ValidationError, StructureNotFoundError) as error:
        print(f"Parse Error: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()