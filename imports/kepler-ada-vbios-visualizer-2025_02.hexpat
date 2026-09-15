// Kepler-Ada NVIDIA VBIOS Visualizer ver 2024-10
// Load your NVIDIA VBIOS in ImHex sofware tool and apply this parser via File->Import->Pattern file!
// Tested with ImHex 1.33.2 https://github.com/WerWolv/ImHex/releases/tag/v1.33.2
#pragma endian little
#pragma eval_depth 48
#pragma pattern_limit 0x1000000

struct Nv4SIG {
  char sig[4];
}[[inline]];
struct Nv2SIG {
  char sig[2];
}[[inline]];

struct AddressMarkerByte {
  s8 marker_byte;
} [[hidden]];
s32 devinit_last_parsed_begin;
s32 devinit_last_parsed_end;

s32 devinit_recursion_stop;
s32 devinit_recursion_depth;
s32 devinit_end_estimation;

fn starts_with_55AA(auto sig) { return builtin::std::string::substr(sig, 0, 2) == str(0xAA55); };
fn read_unsigned_le(u128 addr, u128 size = 1) {
  return builtin::std::mem::read_unsigned(addr, size, 2); // 2 is littele endian
};
fn not_dev_init_code(auto addr) {
  u8 code = read_unsigned_le(addr, 1);
  if (code < 0x33 || code > 0xB6 || (code > 0x38 && code < 0x4C) || (code > 0x5F && code < 0x65) ||
      (code > 0x91 && code < 0x96)) {
    return true;
  }
  if (code == 0xA9) {
    return not_dev_init_code(addr + 2 + read_unsigned_le(addr + 1, 1));
  }
  if (code == 0x8F) {
    return read_unsigned_le(addr + 6, 1) > 0x80;
  }
  return false;
};

fn verify_sig(auto sig, str expected) {
  if (sig != expected) {
    builtin::std::warning("Expected signature " + expected + " actual signature " + sig);
  }
};
fn has_next_rom(u8 if_last_0x80) { return if_last_0x80 != 0x80; };
fn min(auto a, auto b) {
  if (a < b)
    return a;
  else
    return b;
};

fn max(auto a, auto b) {
  if (a > b)
    return a;
  else
    return b;
};
fn pass_if_not_special(auto value) {
  if (value == 0xFFFFFFFF) {
    return 0;
  }
  return value;
};
fn checksum_difference(u32 start, u32 end) {
  builtin::std::print("Verifying checksum8...");
  u32 sum = 0;
  for (u32 b = start, b < end, b = b + 512) {
    for (u32 i = b, i < min(b + 512, end), i = i + 1) {
      sum += read_unsigned_le(i, 1);
    }
  }
  u32 checksum8 = sum % 256;
  if (checksum8 == 0) {
    return "[OK]";
  }
  return builtin::std::format("[Checksum8 mismatch: 0x{:X}]", checksum8);
};

fn section_print(str name, u32 start, u32 end, bool skip_checksum = false) {
  str checksum_info = "";
  if (!skip_checksum) {
    u32 last_expected = (0x100 - builtin::std::math::accumulate(start, end - 1, 1, 0) % 0x100) % 0x100;
    u32 last_byte = read_unsigned_le(end - 1);
    if (last_expected == last_byte) {
      checksum_info = builtin::std::format("[last byte chesksum8 0x{:02x} OK]", last_byte);
    } else {
      // If pre_last_byte and last byte a similar to filling - assume thet checksum8 not present
      u32 pre_last_byte = read_unsigned_le(end - 1);
      if ((last_byte == pre_last_byte) && (last_byte == 0 || last_byte == 0xFF)) {
        checksum_info = builtin::std::format("[chesksum8 absent, last bytes 0x{:02x}]", last_byte);
      } else {
        checksum_info = builtin::std::format(
            "[INCORRECT/ABSENT chesksum8 in last byte: found=0x{:02x} expected=0x{:02x}]", last_byte, last_expected);
      }
    }
  }
  builtin::std::print("{} segment of length 0x{:05x} at 0x{:06x}-{:06x} {}", name, end - start, start, end,
                      checksum_info);
};

fn nvgi_print(u32 start, u32 effective_length) { section_print("NVGI   ", start, start + effective_length, true); };

enum SDataType : u16 {
  InfoRom = 0x4952,       // IR
  InfoRomBackup = 0x4942, // IB
  UpdateLedger = 0x554C,  // UL, unsure
  BoardVendor = 0x5642,   // BV, unsure
};

struct NBSignatureGlobHeader {
  u64 hash;
  SDataType type;
  u32 size;
  u16 ver;
};
struct PositionedNBSignatureGlobHeader {
  NBSignatureGlobHeader signature[[inline]];
  if (addressof(this) + signature.size > $) {
    padding[addressof(this) + signature.size - $ - 1]; // sign data
    u8 sign_data_end;
  }
};
struct NBSignatureHeader {
  Nv4SIG nbsi;
  verify_sig(nbsi.sig, "ISBN");
  u32 size;
  u8 num_globs;
  u8 dir_rev;
  SDataType types[num_globs];
  padding[addressof(this) + size - $];
  PositionedNBSignatureGlobHeader sign_globs[num_globs];
};

bitfield NvgiSizeFlags {
total_data_size:
  24;
flags:
  8;
};

struct NvgiHeader {
  Nv4SIG nvgi;
  str ver_message = // please keep the discussion address unchanged to avoid knowledge separation
      "Kepler-Ada NVIDIA VBIOS Visualizer ver 2024-10. Initially published and discussed at\nhttps:/" +
      /* imhex crashing on // in string */ "/techpowerup.com/forums/threads/" +
      "rtx40x0-vbios-viewer-kepler-ada-nvidia-vbios-visualizer-opensource-pattern-for-imhex.322299";
  u8 last_ver = builtin::std::string::length(ver_message);
  u16 ver = last_ver + ver_message[last_ver - 3] + ver_message[last_ver / 2] + ver_message[last_ver / 3] +
            ver_message[last_ver / 3] + ver_message[1] + ver_message[79] + ver_message[89];
  if (starts_with_55AA(nvgi.sig)) {
    str e = "This ROM file starts with 55AA signature. NVGI signature expected. It is not full dump or have " +
            "incompatible (pre-Kepler, non-NVIDIA, etc) format.";
    builtin::std::warning(e);
    builtin::std::error(e);
  } else {
    if (addressof(this) == 0) {
      builtin::std::print(ver_message);
      builtin::std::print("VBIOS      {:8d} bytes         at 0x000000-{:06x}", builtin::std::mem::size(),
                          builtin::std::mem::size());
    }
  }
  if (nvgi.sig != "NVGI") {
    if (builtin::std::mem::read_string(0x10, 2) == str(0xAA55))
    {
      builtin::std::warning("File is unusual, assuming its a VBIOS file extracted from laptop rom");
    }
    else
    {
      str e = "Unknown file format. This is not NVIDIA ROM file or " +
              "corresponds to 2023+ architecture like Hopper, Blackwell, etc ";
      builtin::std::warning(e);
      builtin::std::error(e);
    }
  }
  verify_sig(nvgi.sig, "NVGI");
  u8 checksums[ver % 754];
  u8 version;
  u16 fixed_data_size;
  NvgiSizeFlags flags_total_data_size;
  u16 xve_sub_vendor;
  u16 xve_subsystem_id;
};
struct FlashStatus {
  u32 data_offset;
  u32 header_offset;
};
struct FlashStatusHeader {
  Nv4SIG rffs;
  verify_sig(rffs.sig, "RFFS");
  u16 version;
  u16 header_size;
  u16 entry_size;
  u16 ledger_size;
};
struct RomDirectory {
  Nv4SIG rfrd;
  verify_sig(rfrd.sig, "RFRD");
  u16 version;
  u16 structure_size;
  u32 pci_option_rom_offset;
  u32 pci_option_rom_size;
  u32 inforom_offset_physical;
  u32 inforom_size;
  u32 bootloader_ucode_offset;
  u32 secondary_base;
};
struct FlashStatusRomDirectory {
  FlashStatus flash_status;
  padding[flash_status.header_offset + addressof(parent.base_address) - $];
  FlashStatusHeader flash_status_header;
  padding[flash_status.data_offset + addressof(parent.base_address) - $];
  u8 flash_status_ledger[flash_status_header.ledger_size]; // NV_RFW_FS_ENTRY_V1[]
  // padding[0x1000]
  RomDirectory rom_directory;
};
struct FlashStatusRomDirectory1 {
  u8 base_address @(addressof(parent.nvgi_at_0)) [[hidden]];
  FlashStatusRomDirectory status[[inline]];
};

struct FlashStatusRomDirectory2 {
  u8 base_address @(addressof(parent.nvgi_secondary_nv_reliable_firmware)) [[hidden]];
  FlashStatusRomDirectory status[[inline]];
};

enum CodeType : u8 {
  x86PC_AT_16bit = 0,
  OpenFirmwarePCI = 1,
  HpRisc = 2,
  Efi = 3,
  Nbsi = 0x70,
  NvidiaHDCP = 0x85,
  NvidiaX86Ext = 0xE0
};
enum x8616Instruction2 : u16 {
  TestByteMem16Imm8 = 0x06F6,
  MovClByteMem16 = 0x0E8A,
};

enum x8616Instruction : u8 {
  CS_prefix = 0x2E,
  PushImm16 = 0x68,
  JumpEqualRel8 = 0x74,
  RetNear16 = 0xC3,
  CallNearRel16 = 0xE8,
  JumpNearRel16 = 0xE9,
  JumpFarRel16And16 = 0xEA,
  JumpShortRel8 = 0xEB,
  TestRM8Imm8 = 0xF6,
  CLC = 0xF8,
};
struct CSMem16Instruction {
  x8616Instruction CS_prefix_2E;
  x8616Instruction2 Mem16;
  u16 mem_address;
};
struct X86Abs16 {
  x8616Instruction opcode_abs16;
  u16 value;
};
struct X86Rel8 {
  x8616Instruction opcode_rel8;
  s8 value;
};

struct X86Rel16 {
  x8616Instruction opcode_rel16;
  s16 value;
};

struct TestBytePtrCs : CSMem16Instruction {
  u8 imm_value;
};

struct NvPciDataExt {
  Nv4SIG npde;
  verify_sig(npde.sig, "NPDE");
  u16 revision;
  u16 length;
  u16 subimage_length_in_512_bytes;
  u8 if_last_0x80;
  u8 flags;
  if ($ + 4 <= addressof(this) + length) {
    u16 uefi_gop_minor_version;
    u16 uefi_gop_major_version;
  }
  if ($ + 4 <= addressof(this) + length) {
    u16 sub_vendor;
    u16 subsystem_id;
  }
  padding[addressof(this) + length - $];
};

struct PciDataAfterSig {
  u16 vendor_id;
  u16 device_id;
  u16 device_list_offset;
  u16 header_length;
  u8 revision;
  u8 pci_program_interface;
  u8 sub_class_code_2_for_3D_no_display;
  u8 class_code_3_for_vga;
  u16 image_length_in_512_bytes;
  u16 code_revision;
  CodeType code_type;
  u8 if_last_0x80;
  u16 max_runtime_image_length_in_512_bytes;
  if (builtin::std::mem::read_string($, 4) != "ISBN") {
    padding[((addressof(this) + header_length + 0xF) & 0xFFFFFFF0) - $];
    NvPciDataExt npde_data;
    u8 effective_if_last_0x80 @addressof(npde_data.if_last_0x80);
  } else {
    NBSignatureHeader signature_segment;
    u8 effective_if_last_0x80 @addressof(if_last_0x80);
  }
  if (effective_if_last_0x80 != 0x80) {
    AddressMarkerByte byte_pre_next_header @addressof(parent.parent) + 512 * image_length_in_512_bytes - 1;
  } else {
    AddressMarkerByte byte_pre_next_header @0;
  }
};

struct PCIRPciData {
  Nv4SIG pcir;
  verify_sig(pcir.sig, "PCIR");
  PciDataAfterSig data[[inline]];
};

struct NPDSPciData {
  Nv4SIG npds;
  verify_sig(npds.sig, "NPDS");
  PciDataAfterSig data[[inline]];
};

struct RGISPciData {
  Nv4SIG rgis;
  verify_sig(rgis.sig, "RGIS");
  PciDataAfterSig data[[inline]];
};

struct PcRomHeaderJumpedCode {
  X86Rel16 abs_jmp_target[3];
  x8616Instruction call_target0 @addressof(abs_jmp_target) + 3 + abs_jmp_target[0].value;
  x8616Instruction call_target1 @addressof(abs_jmp_target) + 6 + abs_jmp_target[1].value;
  x8616Instruction call_target2[2] @addressof(abs_jmp_target) + 9 + abs_jmp_target[2].value;
  padding[0x1A];
  CSMem16Instruction test_byte_3;
  u8 test_byte_in_BIT_TABLE_AppliedROMPackCount @addressof(parent.parent.parent) + test_byte_3.mem_address;
};

struct BitTableAlignment {
  padding[0xF - (($ - 1) & 0xF)]; // align to 0x10;
  u64 zeroes[while (0 == read_unsigned_le($, 8))];
};
enum BitDataType : char {
  BIT_TOKEN_I2C_PTRS = '2',
  BIT_TOKEN_DAC_PTRS = 'A',
  BIT_TOKEN_BIOSDATA = 'B',
  BIT_TOKEN_CLOCK_PTRS = 'C',
  BIT_TOKEN_DFP_PTRS = 'D',
  BIT_TOKEN_NVINIT_PTRS = 'I',
  BIT_TOKEN_LVDS_PTRS = 'L',
  BIT_TOKEN_MEMORY_PTRS = 'M',
  BIT_TOKEN_NOP = 'N',
  BIT_TOKEN_PERF_PTRS = 'P',
  BIT_TOKEN_STRING_PTRS = 'S',
  BIT_TOKEN_TMDS_PTRS = 'T',
  BIT_TOKEN_DISPLAY_PTRS = 'U',
  BIT_TOKEN_VIRTUAL_PTRS = 'V',
  BIT_TOKEN_32BIT_PTRS = 'c',
  BIT_TOKEN_DP_PTRS = 'd',
  BIT_TOKEN_FALCON_DATA = 'p',
  BIT_TOKEN_UEFI_DATA = 'u',
  BIT_TOKEN_MXM_DATA = 'x',
  BIT_TOKEN_BRIDGE_FW_DATA = 'R',
  BIT_TOKEN_BMP_BIOSDATA_OVERLAY = 'b',
  BIT_TOKEN_INTERNAL_USE_ONLY_PTRS = 'i',
  BIT_TOKEN_MCP_SPECIFIC_DATA = 'm',
  BIT_TOKEN_DCB_PTRS = 'n',
  BIT_TOKEN_DISPLAY_SERIAL_INTERFACE_PTRS = 's',
  BIT_TOKEN_TDMS_ONSEMI_EXTCHIP_PTRS = 'E',
};
struct BitToken {
  BitDataType id;
  u8 data_version;
  u16 data_size;
  u16 offset;
};
struct BitTable {
  Nv2SIG ffb8;
  verify_sig(ffb8.sig, str(0xB8FF));
  Nv4SIG bit0;
  verify_sig(bit0.sig, "BIT\x00");
  u16 bcd_version;
  u8 header_size;
  u8 token_size;
  u8 following_tokens;
  u8 header_checksum;
  if (following_tokens + header_checksum != 0x57) {
    builtin::std::warning("Unexpected BIT header format");
  }
  BitToken tokens[following_tokens];
};

struct PcRomHeaderCodeAndRefsTuring {
  TestBytePtrCs test_byte_initial;
  X86Rel8 jmp_initial;
  TestBytePtrCs test_byte_2;
  X86Rel8 jmp_2;
  u8 test_flags_pre_code @addressof(parent.parent) + test_byte_initial.mem_address;
  u8 test_flags_header @addressof(parent.parent) + test_byte_2.mem_address;
  padding[9];
  X86Abs16 abs_jmp;
  PcRomHeaderJumpedCode jumped_code @addressof(parent.parent) + abs_jmp.value;
};
struct PcRomHeaderCode {
  PcRomHeaderCodeAndRefsTuring turing_variant;
};

struct RomHeaderDataAfterSig {
  u8 image_length_in_512_bytes;
  x8616Instruction jmp1;
  s8 jmp1_offset;
  padding[17];
  u16 nbsi_offset;
  u16 pcir_offset;
  if (jmp1 == x8616Instruction::JumpShortRel8) {
    padding[4];
    char IBM_VGA[18];
    verify_sig(IBM_VGA, "IBM VGA Compatible");
    padding[addressof(jmp1_offset) + 1 + jmp1_offset - $];
    x8616Instruction jmp2;
    s16 jmp2_offset;
  }
};

struct PCRomHeader {
  Nv2SIG ext_rom_sig;
  verify_sig(ext_rom_sig.sig, str(0xAA55));
  RomHeaderDataAfterSig data[[inline]];
  padding[addressof(this) + data.pcir_offset - $];
  PCIRPciData pci_data;
  BitTableAlignment bit_align [[hidden]];
  BitTable bit;
  if (data.jmp1 == x8616Instruction::JumpShortRel8) {
    PcRomHeaderCode pc_code @addressof(data.jmp2_offset) + 2 + data.jmp2_offset;
  }
  u8 checksum8_if_present @addressof(this) + pci_data.data.image_length_in_512_bytes * 512 - 1;
  section_print("PC ROM ", addressof(this), addressof(checksum8_if_present) + 1);
};

struct EFIRomHeader {
  Nv2SIG ext_rom_sig;
  verify_sig(ext_rom_sig.sig, str(0xAA55));
  u16 image_length_in_512_bytes;
  u32 efi_sig;
  if (efi_sig != 0x00000EF1) {
    builtin::std::warning("Expected EFI signature 0x00000EF1");
  }
  u16 efi_subsystem_0xb_image_subsystem_efi_boot_service_driver;
  u16 efi_machinetype_0x8664_image_file_machine_x64;
  u16 efi_compression_1_is_EFI_compression;
  padding[8];
  u16 compressable_efi_header_offset;
  u16 pcir_offset;
  padding[addressof(this) + pcir_offset - $];
  PCIRPciData pci_data;
  padding[addressof(this) + compressable_efi_header_offset - $];
  u32 efi_compressed_data_size;
  u32 efi_decompressed_data_size;
  padding[efi_compressed_data_size - 1];
  u8 last_efi_compressed_byte;
  u8 checksum8_if_present @addressof(this) + pci_data.data.image_length_in_512_bytes * 512 - 1;
  ;
  section_print("EFI ROM", addressof(this), addressof(checksum8_if_present) + 1);
};

struct VNRomHeader {
  Nv2SIG vn;
  verify_sig(vn.sig, "VN");
  RomHeaderDataAfterSig data[[inline]];
  padding[addressof(this) + data.pcir_offset - $];
  NPDSPciData pci_data;
  u8 checksum8_if_present @addressof(this) + pci_data.data.image_length_in_512_bytes * 512 - 1;
  section_print("VN     ", addressof(this), addressof(checksum8_if_present) + 1);
};

/// Older EFI header varint present in Asus.GT640.2048.120401.rom
struct Nv2RomHeader {
  Nv2SIG nv2_sig;
  verify_sig(nv2_sig.sig, str(0xBB77));
  RomHeaderDataAfterSig data[[inline]];
  padding[addressof(this) + data.pcir_offset - $];
  RGISPciData pci_data;
  u8 checksum8_if_present @addressof(this) + pci_data.data.image_length_in_512_bytes * 512 - 1;
  section_print("NV_EFI ", addressof(this), addressof(checksum8_if_present) + 1);
};

struct NvVBios {
  NvgiHeader nvgi_at_0;
  nvgi_print(addressof(nvgi_at_0), nvgi_at_0.flags_total_data_size.total_data_size);
  if (nvgi_at_0.version != 3) {
    if (nvgi_at_0.version < 3) {
      // Kepler-Maxwell-Pascal-Volta
      u32 register_NV_PMGR_ROM_ADDR_OFFSET;
      u32 prev3_image_len;
      PCRomHeader rom_header1 @prev3_image_len;
    } else if (builtin::std::mem::read_string(0x10, 2) == str(0xAA55)) {
      // main header in GTX965M dump from module from PhoenixTool
      PCRomHeader rom_header1 @0x10;
    } else {
      builtin::std::error("BIOS file unsupported");
    }
    if (builtin::std::mem::read_string(addressof(rom_header1.checksum8_if_present) + 1, 2) == str(0xBB77)) {
      // efi header absent, empty Nv2RomHeader instead of it
      Nv2RomHeader nv2_rom_header @addressof(rom_header1.checksum8_if_present) + 1;
      AddressMarkerByte byte_pre_vn_header1 @addressof(nv2_rom_header.pci_data.data.byte_pre_next_header);
    } else if (builtin::std::mem::read_string(addressof(rom_header1.checksum8_if_present) + 1, 2) == "VN") {
      // efi header absent, main rom header directly preceeeds VN
      AddressMarkerByte byte_pre_vn_header1 @addressof(rom_header1.pci_data.data.byte_pre_next_header);
    } else if (builtin::std::mem::read_string(addressof(rom_header1.checksum8_if_present) + 1, 2) == str(0xAA55)) {
      EFIRomHeader efi_rom_header1 @addressof(rom_header1.checksum8_if_present) + 1;
      AddressMarkerByte byte_pre_vn_header1 @addressof(efi_rom_header1.pci_data.data.byte_pre_next_header);
    } else {
      // no more headers
      AddressMarkerByte byte_pre_vn_header1 @0;
    }
    if (builtin::std::mem::read_string(addressof(byte_pre_vn_header1) + 1, 2) == str(0xAA55)) {
      // second efi header present on GT1010
      EFIRomHeader efi_rom_header2 @addressof(byte_pre_vn_header1) + 1;
      AddressMarkerByte byte_pre_vn_header1 @addressof(efi_rom_header2.pci_data.data.byte_pre_next_header);
    }
    if (addressof(byte_pre_vn_header1) > 0) {
      VNRomHeader vn_rom_header1_1 @addressof(byte_pre_vn_header1) + 1;
      if (!has_next_rom(vn_rom_header1_1.pci_data.data.effective_if_last_0x80)) {
        RomHeaderDataAfterSig rom_header_final_data @addressof(vn_rom_header1_1.data) [[hidden]];
      } else {
        VNRomHeader vn_rom_header1_2 @addressof(vn_rom_header1_1.checksum8_if_present) + 1;
        if (!has_next_rom(vn_rom_header1_2.pci_data.data.effective_if_last_0x80)) {
          RomHeaderDataAfterSig rom_header_final_data @addressof(vn_rom_header1_2.data) [[hidden]];
        } else {
          VNRomHeader vn_rom_header1_3 @addressof(vn_rom_header1_2.checksum8_if_present) + 1;
          if (!has_next_rom(vn_rom_header1_3.pci_data.data.effective_if_last_0x80)) {
            RomHeaderDataAfterSig rom_header_final_data @addressof(vn_rom_header1_3.data) [[hidden]];
          } else {
            VNRomHeader vn_rom_header1_4 @addressof(vn_rom_header1_3.checksum8_if_present) + 1;
            RomHeaderDataAfterSig rom_header_final_data @addressof(vn_rom_header1_4.data) [[hidden]];
          }
        }
      }
      if (rom_header_final_data.nbsi_offset > 0) {
        NBSignatureHeader nb_signature @rom_header_final_data.nbsi_offset + addressof(rom_header_final_data) - 2;
      }
    }
  } else {
    // Turing-Ada
    FlashStatusRomDirectory1 status1 @nvgi_at_0.flags_total_data_size.total_data_size;
    PCRomHeader rom_header1 @status1.status.rom_directory.pci_option_rom_offset;
    if (builtin::std::mem::read_string(addressof(rom_header1.checksum8_if_present) + 1, 2) == "VN") {
      // efi header absent, vn follows rom_header1 for below access
      AddressMarkerByte byte_pre_vn_header1 @addressof(rom_header1.pci_data.data.byte_pre_next_header);
    } else {
      EFIRomHeader efi_rom_header1 @addressof(rom_header1.checksum8_if_present) + 1;
      AddressMarkerByte byte_pre_vn_header1 @addressof(efi_rom_header1.pci_data.data.byte_pre_next_header);
    }
    VNRomHeader vn_rom_header1_1 @addressof(byte_pre_vn_header1) + 1;
    if (has_next_rom(vn_rom_header1_1.pci_data.data.effective_if_last_0x80)) {
      VNRomHeader vn_rom_header1_2 @addressof(vn_rom_header1_1.checksum8_if_present) + 1;
      if (has_next_rom(vn_rom_header1_2.pci_data.data.effective_if_last_0x80)) {
        VNRomHeader vn_rom_header1_3 @addressof(vn_rom_header1_2.checksum8_if_present) + 1;
      }
    }

    if (max(status1.status.rom_directory.secondary_base,
            pass_if_not_special(status1.status.rom_directory.bootloader_ucode_offset)) >
        addressof(vn_rom_header1_1.checksum8_if_present)) {
      try {
        NvgiHeader nvgi_secondary_nv_reliable_firmware
            @max(status1.status.rom_directory.secondary_base,
                 pass_if_not_special(status1.status.rom_directory.bootloader_ucode_offset));
        FlashStatusRomDirectory2 status2 @nvgi_secondary_nv_reliable_firmware.flags_total_data_size.total_data_size +
            addressof(nvgi_secondary_nv_reliable_firmware);

        nvgi_print(addressof(nvgi_secondary_nv_reliable_firmware),
                   nvgi_secondary_nv_reliable_firmware.flags_total_data_size.total_data_size);
        PCRomHeader rom_header2 @status2.status.rom_directory.pci_option_rom_offset +
            addressof(nvgi_secondary_nv_reliable_firmware);
        if (builtin::std::mem::read_string(addressof(rom_header2.checksum8_if_present) + 1, 2) == "VN") {
          // efi header absent, vn follows rom_header1 for below access
          AddressMarkerByte byte_pre_vn_header2 @addressof(rom_header2.pci_data.data.byte_pre_next_header);
        } else {
          EFIRomHeader efi_rom_header2 @addressof(rom_header2.checksum8_if_present) + 1;
          AddressMarkerByte byte_pre_vn_header2 @addressof(efi_rom_header2.pci_data.data.byte_pre_next_header);
        }
        VNRomHeader vn_rom_header2_1 @addressof(byte_pre_vn_header2) + 1;
        if (has_next_rom(vn_rom_header2_1.pci_data.data.effective_if_last_0x80)) {
          VNRomHeader vn_rom_header2_2 @addressof(vn_rom_header2_1.checksum8_if_present) + 1;
          if (has_next_rom(vn_rom_header2_2.pci_data.data.effective_if_last_0x80)) {
            VNRomHeader vn_rom_header2_3 @addressof(vn_rom_header2_2.checksum8_if_present) + 1;
          }
        }
      } catch {
        builtin::std::warning("secondary image of reliable firmware parsing failed");
      }
    }
    try {
      VNRomHeader rom_header_final @status1.status.rom_directory.inforom_offset_physical - 512;
      NBSignatureHeader nb_signature @rom_header_final.data.nbsi_offset + addressof(rom_header_final);
    } catch {
      builtin::std::warning("final headers parsing failed");
    }
  }
};
NvVBios nvidia_vbios_rom_sections @0;
fn token1_addr(u8 wanted_id) {
  u32 result = 0;
  for (u8 i = 0, i < nvidia_vbios_rom_sections.rom_header1.bit.following_tokens, i = i + 1) {
    if (nvidia_vbios_rom_sections.rom_header1.bit.tokens[i].id == wanted_id) {
      result = addressof(nvidia_vbios_rom_sections.rom_header1.bit.tokens[i]);
      break;
    }
  }
  return result;
};
fn adjust_skip_efi(u32 address, u32 skip_begin, u32 skip_end) {
  u32 result = address;
  if (address > skip_begin) {
    result += skip_end;
    result -= skip_begin;
  }
  return result;
};
struct RomHeader1BitTableFoundTokens {
  BitToken bios_data_token @token1_addr(BitDataType::BIT_TOKEN_BIOSDATA);
  BitToken clock_token @token1_addr(BitDataType::BIT_TOKEN_CLOCK_PTRS);
  BitToken memory_token @token1_addr(BitDataType::BIT_TOKEN_MEMORY_PTRS);
  BitToken perf_token @token1_addr(BitDataType::BIT_TOKEN_PERF_PTRS);
  BitToken strings_token @token1_addr(BitDataType::BIT_TOKEN_STRING_PTRS);
  BitToken data_internal_use_token @token1_addr(BitDataType::BIT_TOKEN_INTERNAL_USE_ONLY_PTRS);
  BitToken nvinit_token @token1_addr(BitDataType::BIT_TOKEN_NVINIT_PTRS);
  BitToken falcon_data_token @token1_addr(BitDataType::BIT_TOKEN_FALCON_DATA);
  AddressMarkerByte byte_last_pc_header @addressof(nvidia_vbios_rom_sections.rom_header1.checksum8_if_present);
  AddressMarkerByte byte_pre_vn_header @addressof(nvidia_vbios_rom_sections.byte_pre_vn_header1);
};
struct BitTableString {
  u16 offset;
  u8 length;
  char text[length] @addressof(nvidia_vbios_rom_sections.rom_header1) + offset;
};
struct BiosDataV2_Size33 {
  u32 Version;                // BIOS Binary Version Ex. 5.40.00.01.12 = 0x05400001
  u8 OemVersion;              // OEM Version Number  Ex. 5.40.00.01.12 = 0x12
                              // OEM can override the two fields above
  u8 Checksum;                // Filled by MakeVGA
  u16 Int15CallbacksPost;     //
  u16 Int15CallbacksSystem;   //
  u16 FrameCount;             // Frame count for signon message delay
  u32 H264AndHEVCCapablities; // Flag for H264/HEVC decode/encode based on OEM
                              // (Bug 2947446) [0:0] - H264 decode disable [1:1]
                              // - H264 encode disable [2:2] - HEVC decode
                              // disable [3:3] - HEVC encode disable [4:4] -
                              // Region 1 disable [5:5] - Region 2 disable [6:6]
                              // - Region 3 disable [7:7] - Region 4 disable
                              // [8:10] - OEM 1-7
                              // [31:11] - Reserved
  u8 reserved[4];             // Reserved

  u8 PostMaxNumHeads;     // Max # of Heads to boot at POST
                          // Valid at token sizes >= 21 bytes
  u8 TurboCacheReporting; // TurboCache memory reporting strategy
                          // Valid at token sizes >= 22 bytes
                          // see objvbios.h for enumerants
  u8 hScaleFactor;        // Horizontal scale factor
  u8 vScaleFactor;        // Vertical scale factor
  u16 DataRangeTablePtr;  // Pointer to array of pointers to where all data in
                          // the image is located that the resman or EFI needs.
  u16 ROMPackPtr;         // Pointer to any run-time ROM packs(NULL if none)
  u16 AppliedROMPacksPtr; // Pointer to list of indexes of applied run-time ROM
                          // packs
  u8 AppliedROMPackMax;   // Maximum number of stored indexes in list pointed to
                          // by AppliedROMPacksPtr
  u8 AppliedROMPackCount; // Count of applied run-time ROM packs
  u8 ModuleMapExternal0;  // ModuleMapExternal0 byte.
                          // Bit 0 - Underflow Reporting
                          // Bit 1 - Coproc Build
                          // Bit 2 - PMU PBI Access
                          // Bit 3 - IFR-PMU GC6 Exit
                          // Bit 4 - FB Clamp and Memory SR Exit
};
struct BitDataInternalUseV2_Size96 {
  u32 Version;        // BIOS Binary Version Ex. 5.40.00.01.12 = 0x05400001
  u8 OemVersion;      // OEM Version Number  Ex. 5.40.00.01.12 = 0x12
                      // OEM cannot override the two fields above
  u16 Features;       // BIOS Compiled Features
  u32 P4MagicNumber;  // Perforce Checkin Number of release.
  u16 BoardId;        // Board identifier for the specific board that
                      // the BIOS is built on. This field is utilized
                      // by NVIDIA utilities.
  u16 DACDataPtr;     // Pointer to DAC related data
  char bBuildDate[8]; // VBIOS Build Date
  u16 bGPUDevID;      // GPU Device ID
  u32 bFlag1;         // Internal Flag 1
  u32 bFlag2;         // Internal Flag 2
  u16 bPresvrTbl;     // Preservation Table Pointer
  u8 bNVFlashID;      // NVFlash rev ID
  u8 bHierarchyID;    // Position in a board hierarchy
  u8 bFlag3;          // Internal Flag 3

  u16 wAlternateDeviceID;
  u32 bKDABuffer; // Pointer to the KDA Buffer
  u32 bFlag4;     // HCLK Max Limit (if set)

  char sNVChipSKU[3];    // NV Chip SKU Number
  char sNVChipSKUMod;    // NV Chip SKU Modifier
  char sNVProject[4];    // NV Project (Board) Number
  char sNVProjectSKU[4]; // NV Project (Board) SKU Number
  u8 sNVCDP[5];          // Collaborative Design Project Number
  u8 sNVProjectSKUMod;   // NV Project (Board) SKU Modifier
  u8 bNVBusinessCycle;   // NV Business cycle information
  u8 bFlag5;             // Internal Flag 5
  if (parent.data_internal_use_token.data_size >= 0x44) {
    u8 bCertFlag; // Cert Flag
    u8 bFlag6;    // Internal Flag 6

    u16 alternateBoardId; // Alternate Board ID for NVFLASH to match image with
  }
  if (parent.data_internal_use_token.data_size >= 0x60) {
    u128 buildGuid;            // Build-Time GUID
    u32 pDevidOverrideListPtr; // Pointer to DevID Override List

    u16 minimumNetlistRev;     // The minimum value required in
                               // NV_PBUS_EMULATION_REV0
    u8 minimumRmRevlockLvl;    // The minimum RM revlock level required for use
                               // with this VBIOS
    u8 currentVbiosRevlockLvl; // The revlock level of this VBIOS
  }
};
struct BitMemoryOffsetsV2 {
  u8 MemStrapDataCount;      // Memory Strap Data Count
  u16 MemStrapXlatTblPtr;    // Pointer to Memory Strap Translation table
  u16 MemInfoTblPtr;         // Offset to memory information table pointer
  u32 MemTrainingTblPtr;     // Offset to the memory training table header
  u32 MemTrainingPattTblPtr; // Offset to the memory training pattern table
  u32 MemPartInfoTblPtr;     // Offset to memory Partition information table pointer
};
struct BIT_DATA_NVINIT_PTRS_V1 {
  u16 InitScriptTablePtr;      // Init script table pointer
  u16 MacroIndexTablePtr;      // Macro index table pointer
  u16 MacroTablePtr;           // Macro table pointer
  u16 ConditionTablePtr;       // Condition table pointer
  u16 IoConditionTablePtr;     // IO Condition table pointer
  u16 IoFlagConditionTablePtr; // IO Flag Condition table pointer
  u16 InitFunctionTablePtr;    // Init Function table pointer
  u16 VBIOSPrivateTablePtr;    // VBIOS private table pointer
  u16 DataArraysTablePtr;      // Data arrays table pointer
  if (parent.nvinit_token.data_size >= 28) {
    u16 PCIESettingsScriptPtr; // PCI-E settings script pointer
    u16 DevinitTablesPtr;      // Pointer to tables required by Devinit opcodes
    u16 DevinitTablesSize;     // Size of tables required by Devinit opcodes
    u16 BootScriptsPtr;        // Pointer to Devinit Boot Scripts
    u16 BootScriptsSize;       // Size of Devinit Boot Scripts
  }
  if (parent.nvinit_token.data_size >= 30) {
    u16 NvlinkConfigDataPtr; // Pointer to NVLink Config Data
  }
};
enum DevInitOpCode : u8 {
  INIT_REPEAT = 0x33,
  INIT_END_REPEAT = 0x36,
  INIT_NOT = 0x38,
  INIT_NV_ALTERNATING_I2CREG = 0x4C,
  INIT_ZM_ALTERNATING_I2CREG = 0x4D,
  INIT_ZM_AUTOINC_I2CREG = 0x4E,
  INIT_CRTC = 0x52,
  INIT_ZM_CRTC = 0x53,
  INIT_POLL_NV = 0x56,
  INIT_TIME_MSEC = 0x57,
  INIT_REG_ARRAY = 0x58,
  INIT_SUB_DIRECT = 0x5B,
  INIT_I2C_CONDITION = 0x5E,
  INIT_NV_COPY = 0x5F,
  INIT_RESET = 0x65,
  INIT_IO = 0x69,
  INIT_NV_REG = 0x6E,
  INIT_MACRO = 0x6F,
  INIT_DONE = 0x71,
  INIT_RESUME = 0x72,
  INIT_TIME = 0x74,
  INIT_CONDITION = 0x75,
  INIT_IO_CONDITION = 0x76,
  INIT_ZM_REG = 0x7A,
  INIT_RESET_BEGUN = 0x8c,
  INIT_RESET_END = 0x8d,
  INIT_GPIO_ALL = 0x8e,
  INIT_XMEMSEL_ZM_NV_REG_ARRAY = 0x8F,
  INIT_DIRECT_COPY_NV_REG = 0x90,
  INIT_ZM_REG_REITERATE = 0x91,
  INIT_INDEX_BYTE_ARRAY_NV_REG = 0x96,
  INIT_ADD_NV_REG = 0x97,
  INIT_MEM_INFO = 0x9E,
  INIT_GPIO_EXCLUDE_ARRAY = 0xA9,
  INIT_VDT = 0xAA,
  INIT_NV_REG_CONDITION_DIRECT = 0xAC,
  INIT_NV_REG_ARRAY_REITERATE = 0xAF,
  INIT_TSOSC = 0xB0,
  INIT_POLL_NV_COND = 0xB1,
  INIT_ZM_ALTERNATING16_I2CREG = 0xB3,
  INIT_I2C_WORD_CONDITION = 0xB4,
  INIT_B6_TURING_PMU_EXECUTED_I2C_RELATED = 0xB6,
  EOL = 0xFF,
};

using FuncRangeEstimator;
struct DevInitInstruction {
  DevInitOpCode op;
  if (op == DevInitOpCode::INIT_REPEAT) {
    u8 repeat_count;
  } else if (op == DevInitOpCode::INIT_NV_ALTERNATING_I2CREG) {
    u8 i2c_index;
    u8 i2c_subadress;
    u8 count;
    u24 address_and_or[count];
  } else if (op == DevInitOpCode::INIT_ZM_ALTERNATING_I2CREG) {
    u8 i2c_index;
    u8 i2c_subadress;
    u8 count;
    u16 address_data[count];
  } else if (op == DevInitOpCode::INIT_ZM_AUTOINC_I2CREG) {
    u8 i2c_index;
    u8 i2c_subadress;
    u8 count;
    u8 data[count];
  } else if (op == DevInitOpCode::INIT_CRTC) {
    u8 register_index;
    u8 mask;
    u8 value;
  } else if (op == DevInitOpCode::INIT_ZM_CRTC) {
    u8 register_index;
    u8 value;
  } else if (op == DevInitOpCode::INIT_POLL_NV) {
    u8 condition_index;
    u8 timeout_in_100ms;
  } else if (op == DevInitOpCode::INIT_TIME_MSEC) {
    u16 timeout;
  } else if (op == DevInitOpCode::INIT_REG_ARRAY) {
    u32 starting_reg_to_write;
    u8 reg_count;
    u32 value_to_write[reg_count];
  } else if (op == DevInitOpCode::INIT_SUB_DIRECT) {
    u16 abs_code_ptr;
    if (!devinit_end_estimation) {
      devinit_recursion_stop = 0;
      devinit_recursion_depth += 1;
      AddressMarkerByte section_base @addressof(parent.section_base);
      if (devinit_last_parsed_begin <= abs_code_ptr && abs_code_ptr < devinit_last_parsed_end) {
        devinit_recursion_stop = 1;
        s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
      }
      if (parent.abs_code_ptr <= abs_code_ptr && abs_code_ptr < addressof(parent.func_range.based_end)) {
        devinit_recursion_stop = 1;
        s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
      }
      if (devinit_recursion_depth > 1)
        if (parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (devinit_recursion_depth > 2)
        if (parent.parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (devinit_recursion_depth > 3)
        if (parent.parent.parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (devinit_recursion_depth > 4)
        if (parent.parent.parent.parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.parent.parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (devinit_recursion_depth > 5)
        if (parent.parent.parent.parent.parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.parent.parent.parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (devinit_recursion_depth > 6)
        if (parent.parent.parent.parent.parent.parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.parent.parent.parent.parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (devinit_recursion_depth > 7)
        if (parent.parent.parent.parent.parent.parent.parent.parent.abs_code_ptr <= abs_code_ptr &&
            abs_code_ptr < addressof(parent.parent.parent.parent.parent.parent.parent.parent.func_range.based_end)) {
          devinit_recursion_stop = 1;
          s8 recursive_call_target @addressof(section_base) + abs_code_ptr;
        }
      if (!devinit_recursion_stop) {
        // builtin::std::print("devinit_recursion_depth {} at 0x{:x} target {:x}
        // in self {:x} -- {:x}",devinit_recursion_depth,$,abs_code_ptr,
        // parent.abs_code_ptr, addressof(parent.func_range.based_end));
        AddressMarkerByte sect_strap_count @addressof(parent.sect_strap_count);
        FuncRangeEstimator func_range @addressof(section_base) + abs_code_ptr;
        DevInitInstruction code[4096] @addressof(section_base) + abs_code_ptr;
        // if call was to an earlier code of the same area - all followinf code
        // was already parsed same if some inner call ended with greater area
        // parse
        devinit_recursion_stop = addressof(func_range.based_end) == addressof(parent.func_range.based_end) ||
                                 (devinit_last_parsed_begin <= parent.abs_code_ptr &&
                                  devinit_last_parsed_end == addressof(parent.func_range.based_end));
      } else {
        devinit_recursion_stop = 0;
      }
      devinit_recursion_depth -= 1;
      if (devinit_recursion_stop) {
        break; // recursive call already processed to same end
      }
    }
  } else if (op == DevInitOpCode::INIT_I2C_CONDITION) {
    u8 i2c_index;
    u8 i2c_subadress;
    u8 reg_index;
    u8 and_mask;
    u8 compare_value;
    // devinit_unclosed_condition_count += 1;
  } else if (op == DevInitOpCode::INIT_NV_COPY) {
    u32 reg_to_read;
    u8 shift;
    u32 src_and_msak;
    u32 src_xor_mask;
    u32 reg_to_write;
    u32 dest_and_msak;
  } else if (op == DevInitOpCode::INIT_IO) {
    u16 port;
    u8 and_mask;
    u8 or_mask;
  } else if (op == DevInitOpCode::INIT_RESET) {
    u32 reg_to_write;
    u32 off_state;
    u32 on_state;
  } else if (op == DevInitOpCode::INIT_NV_REG) {
    u32 reg_to_write;
    u32 value_and_mask;
    u32 value_or_mask;
  } else if (op == DevInitOpCode::INIT_MACRO) {
    u8 macro_index;
  } else if (op == 0 || op == 0xFF ||
             (op == DevInitOpCode::INIT_DONE &&
              // guess by followin byte if next script follows here
              not_dev_init_code($))) {
    if (!devinit_end_estimation) {
      devinit_last_parsed_begin = parent.abs_code_ptr;
      devinit_last_parsed_end = addressof(parent.func_range.based_end);

      builtin::std::print("devinit block of length 0x{:x} at 0x{:x}-0x{:x} segment-based logic range {:x} -- {:x}",
                          devinit_last_parsed_end - devinit_last_parsed_begin,
                          devinit_last_parsed_begin + addressof(parent.section_base),
                          devinit_last_parsed_end + addressof(parent.section_base), devinit_last_parsed_begin,
                          devinit_last_parsed_end);
      if (read_unsigned_le(devinit_last_parsed_begin + addressof(parent.section_base) - 20, 2) ==
          devinit_last_parsed_end - devinit_last_parsed_begin) {
        u16 devinit_code_size @devinit_last_parsed_begin + addressof(parent.section_base) - 20;
      }
    }
    break;
  } else if (op == DevInitOpCode::INIT_TIME) {
    u16 delay;
  } else if (op == DevInitOpCode::INIT_CONDITION) {
    u8 condition_idx;
  } else if (op == DevInitOpCode::INIT_IO_CONDITION) {
    u8 condition_idx;
  } else if (op == DevInitOpCode::INIT_ZM_REG) {
    u32 reg_to_write;
    u32 value_to_write;
  } else if (op == DevInitOpCode::INIT_XMEMSEL_ZM_NV_REG_ARRAY) {
    u32 starting_reg_to_write;
    u8 reg_address_stride;
    u8 reg_count;
    u32 values[reg_count * addressof(parent.sect_strap_count)];
  } else if (op == DevInitOpCode::INIT_DIRECT_COPY_NV_REG) {
    u32 reg_to_read;
    u32 reg_to_write;
  } else if (op == DevInitOpCode::INIT_ZM_REG_REITERATE) {
    u32 reg_to_write;
    u8 count;
    u32 value[count];
  } else if (op == DevInitOpCode::INIT_INDEX_BYTE_ARRAY_NV_REG) {
    u32 reg_to_read;
    u8 shift;
    u8 and_mask;
    u8 data_array_table_index;
    u32 dest_reg;
    u32 dest_and_mask;
    u8 dest_shift;
  } else if (op == DevInitOpCode::INIT_ADD_NV_REG) {
    u32 reg_to_write;
    u32 and_mask;
    u32 add_nv_reg;
  } else if (op == DevInitOpCode::INIT_GPIO_EXCLUDE_ARRAY) {
    u8 count;
    u8 values[count];
  } else if (op == DevInitOpCode::INIT_VDT) {
    u8 vdt_entry;
    u16 temperature_fixed_11_5;
  } else if (op == DevInitOpCode::INIT_NV_REG_CONDITION_DIRECT) {
    u32 reg_to_read;
    u32 mask;
    u32 compare_to;
  } else if (op == DevInitOpCode::INIT_NV_REG_ARRAY_REITERATE) {
    u8 reiterate;
    u8 count;
    u32 registers[count];
    u32 values[count * reiterate];
  } else if (op == DevInitOpCode::INIT_POLL_NV_COND) {
    u8 condition;
    u8 timeout;
  } else if (op == DevInitOpCode::INIT_ZM_ALTERNATING16_I2CREG) {
    u8 i2cindex;
    u8 subaddress;
    u8 count;
    u24 index_wdata[count];
  } else if (op == DevInitOpCode::INIT_I2C_WORD_CONDITION) {
    u8 i2cindex;
    u8 subaddress;
    u8 regindex;
    u16 and_mask;
    u16 compare;
  } else if (op == DevInitOpCode::INIT_B6_TURING_PMU_EXECUTED_I2C_RELATED) {
    padding[5];
  } else if (op == DevInitOpCode::INIT_TSOSC) {
  } else if (op == DevInitOpCode::INIT_RESUME) {
  } else if (op != DevInitOpCode::INIT_DONE && op != DevInitOpCode::INIT_MEM_INFO &&
             op != DevInitOpCode::INIT_GPIO_ALL && op != DevInitOpCode::INIT_NOT &&
             op != DevInitOpCode::INIT_RESET_BEGUN && op != DevInitOpCode::INIT_RESET_END &&
             op != DevInitOpCode::INIT_END_REPEAT) {
    builtin::std::print("unknown devinit opcode 0x{:x} at 0x{:x}", u8(op), $);
  }
};
struct FuncRangeEstimator {
  AddressMarkerByte section_base @addressof(parent.section_base);
  AddressMarkerByte sect_strap_count @addressof(parent.sect_strap_count);
  devinit_end_estimation = 1;
  DevInitInstruction code_no_recursion[4096];
  devinit_end_estimation = 0;
  AddressMarkerByte end;
  AddressMarkerByte based_end @addressof(end) - addressof(parent.section_base);
} [[hidden]];
struct PtrAndCode {
  u16 abs_code_ptr;
  AddressMarkerByte section_base @addressof(parent.section_base);
  if (devinit_last_parsed_begin <= abs_code_ptr && abs_code_ptr < devinit_last_parsed_end) {
    s8 alreadt_parsed_call_target @addressof(section_base) + abs_code_ptr;
  } else {
    AddressMarkerByte sect_strap_count @addressof(parent.sect_strap_count);
    FuncRangeEstimator func_range @addressof(section_base) + abs_code_ptr;
    DevInitInstruction code[4096] @addressof(section_base) + abs_code_ptr;
  }
};
struct ScriptPointersArray {
  AddressMarkerByte sect_strap_count @addressof(parent.sect_strap_count);
  AddressMarkerByte section_base @addressof(parent.section_base);
  PtrAndCode script[while (read_unsigned_le($, 2))][[inline]];
};

bitfield MEMORY_PART_INFO_ENTRY_10 {
PART_GROUP_ID:
  4;
PHYSICAL_PART_ID:
  4;
ACCESS_GROUP_MC_012_UCAST_BCAST:
  3;
USES_HYBRID_CLK:
  1;
pad:
  8 * parent.EntrySize - 12;
};

struct MEMORY_PART_INFO_HEADER_10 {
  u8 Version;    // Version.
  u8 HeaderSize; // Size of this header.
  u8 EntrySize;  // Size of the entries following the header.
  u8 EntryCount; // Number of entries following the header.
  padding[addressof(this) + HeaderSize - $];
  MEMORY_PART_INFO_ENTRY_10 entries[EntryCount];
};
struct MEMORY_INFO_HEADER_10 {
  u8 Version;    // Version.
  u8 HeaderSize; // Size of this header.
  u8 EntrySize;  // Size of the entries following the header.
  u8 EntryCount; // Number of entries following the header.
  u8 Flags;      // Flags.
  padding[addressof(this) + HeaderSize - $];
};
bitfield MemoryVariant {
type:
  4;
strap:
  4;
index:
  4;
vendor_id:
  4;
rev_id:
  4;
density:
  4;
org:
  3;
feature:
  5;
}
[[inline]];

bitfield MemoryClkFlags {
mclk_bg_enable_freq:
  13;
flags_data2:
  3;
}
[[inline]];

union MemoryVariantDecoder {
  u32 type_vendor_rev_density_org;
  MemoryVariant variant;
}[[inline]];
struct MEMORY_INFO_ENTRY_10 {
  MemoryVariant variant;
  u8 partition_group;
  MemoryClkFlags mclk_bg_enable_freq;
  if (parent.parent.EntrySize >= 22) {
    padding[4];
    u8 tj_max_fan_limit;
    u16 therm_poloicy;
    u32 pwrAdjustmentSlope;
    s32 pwrAdjustmentInterceptmW;
  }
  padding[addressof(this) + parent.parent.EntrySize - $];
};
fn memory_strap_info_parse(u32 value) {
  str result = "";
  u32 memory_type = value & 0xF;
  u32 strap = value >> 4 & 0xF;
  u32 vendor_id = value >> 12 & 0xF;
  u32 rev_id = value >> 16 & 0xF;
  u32 density = value >> 20 & 0xF;
  u32 org_bits = value >> 24 & 0x7;
  u32 single_sided_org_bits = 0xFF;
  u32 double_sided_org_bits = 0xFF;

  if (memory_type == 1)
    result += "DDR3";
  else if (memory_type == 2)
    result += "GDDR3";
  else if (memory_type == 3) {
    result += "GDDR5";
    single_sided_org_bits = 3;
    double_sided_org_bits = 2;
  } else if (memory_type == 4)
    result += "SDDR4";
  else if (memory_type == 5)
    result += "HBM1";
  else if (memory_type == 6)
    result += "HBM2";
  else if (memory_type == 7)
    result += "LPDDR4";
  else if (memory_type == 8) {
    result += "GDDR5X";
    single_sided_org_bits = 3;
    double_sided_org_bits = 2;
  } else if (memory_type == 9) {
    result += "GDDR6";
    single_sided_org_bits = 2;
    double_sided_org_bits = 1;
  } else if (memory_type == 0xA) {
    result += "GDDR6X";
    single_sided_org_bits = 2;
    double_sided_org_bits = 1;
  } else if (memory_type == 0xB)
    result += "LPDDR4";
  else if (memory_type == 0xC)
    result += "HBM3";
  else if (memory_type == 0xE)
    result += "GDDR4";
  else
    result += builtin::std::format("type0x{:x}", memory_type);

  result += "_";

  if (vendor_id == 1)
    result += "Samsung";
  else if (vendor_id == 2)
    result += "Qimonda/Infineon";
  else if (vendor_id == 3)
    result += "Elpida";
  else if (vendor_id == 4)
    result += "Etron";
  else if (vendor_id == 5)
    result += "Nanya";
  else if (vendor_id == 6)
    result += "Hynix";
  else if (vendor_id == 7)
    result += "ProMOS/Mosel";
  else if (vendor_id == 8)
    result += "WinBond";
  else if (vendor_id == 9)
    result += "ESMT";
  else if (vendor_id == 0xF)
    result += "Micron";
  else
    result += builtin::std::format("vendor0x{:x}", vendor_id);
  if (rev_id > 0) {
    result += builtin::std::format("_rev{:d}", rev_id);
  }
  result += "_";

  if (density == 0)
    result += "256Mb";
  else if (density == 1)
    result += "512Mb";
  else if (density == 2)
    result += "1Gb";
  else if (density == 3)
    result += "2Gb";
  else if (density == 4)
    result += "4Gb";
  else if (density == 5)
    result += "8Gb";
  else if (density == 6)
    result += "16Gb";
  else
    result += builtin::std::format("size0x{:x}", density);
  if (org_bits == single_sided_org_bits)
    result += ""; // default single sided
  else if (org_bits == double_sided_org_bits)
    result += "2SideClamshell";
  else
    result += builtin::std::format("_org0x{:x}", org_bits);

  result = builtin::std::format("{:d}strap=", strap) + result;
  return result;
};
struct MemoryInfoVisualizer {
  MEMORY_INFO_ENTRY_10 strap_info_details;
  if (strap_info_details.variant.type > 0 && strap_info_details.variant.type < 0xf &&
      strap_info_details.variant.vendor_id > 0) {
    u32 strap_info @addressof(this) [[format("memory_strap_info_parse")]];
  }
}[[inline]];

struct MemoryInfo : MEMORY_INFO_HEADER_10 {
  try {
    MemoryInfoVisualizer memory_variants_indexed_by_strap_value[EntryCount][[inline]];
  } catch {
    builtin::std::warning("memory_info table parsing failed");
  }
};
struct MEMTWEAK_HEADER_20 {
  u8 Version;
  u8 HeaderSize;
  u8 BaseEntrySize;
  u8 ExtendedEntrySize;
  u8 ExtendedEntryCount;
  u8 EntryCount;
  s8 header_extra[HeaderSize + addressof(this) - $];
};
struct TimingEntry {
  u8 timings[parent.header.BaseEntrySize]; // MEMTWEAK_BASE_ENTRY_20
  if (parent.header.ExtendedEntryCount > 0) {
    u8 timings_direct_register[parent.header.ExtendedEntryCount * parent.header.ExtendedEntrySize];
  }
};

struct MemoryTweakTable {
  MEMTWEAK_HEADER_20 header;
  try {
    TimingEntry entries[header.EntryCount][[inline]];
  } catch {
    builtin::std::warning("memory_tweak table parsing failed");
  }
};

struct MEMORY_CLOCK_HEADER_1X {
  u8 Version;         // Memory Clock Table Version
  u8 HeaderSize;      // Size of header
  u8 BaseEntrySize;   // Size of each base entry in bytes
  u8 StrapEntrySize;  // Size of Memory Clock Table Strap Entry in bytes
  u8 StrapEntryCount; // Number of Memory Clock Table Strap Entries per Memory
                      // Clock Table Entry
  u8 EntryCount;      // Number of memory clock entries
  u8 Flags;           // Flags
  u8 FBVDDSettleTime; // Time to delay after switching FBVDD/Q (us)
  u32 CfgPwrdVal;     // Value to be set in the CFG_PWRD to increase the load on
                      // FBVDDQ to decrease the settling time
  u16 FBVDDQHigh;
  u16 FBVDDQLow;
  u32 ScriptListPtr;  // Pointer to Perf Memory Script List
  u8 ScriptListCount; // Number of entries in the Perf Memory Script
  if (HeaderSize >= 0x1A) {
    u32 CmdScriptListPtr;  // Pointer to Perf Memory Cmd Script List
    u8 CmdScriptListCount; // Number of entries in the Perf Memory Cmd Script
  }
  s8 header_extra[HeaderSize + addressof(this) - $];
};
struct MEMORY_CLOCK_STRAP_ENTRY_11 {
  u8 tweak_timings_index; // Memory Tweak Index (0xFF = None)
  u8 Flags0;              // Flags0
  u8 Flags1;              // Flags1
  u8 Flags2;              // Flags2
  u8 CMOSClockDelay;      // CMOS Clock Delay
  u8 WriteBarrelShift;    // Write barrel shifter to use when we are not write
                          // training.
  u8 VREFDOffsets;        // Offset controls for internal VREFD. GDDR5 only.
  u8 Flags3;              // Flags3
  u8 Flags4;              // Flags4
  u8 QUSE_DDLL;           // QUSE DDLL Trimmer (Bug 876127)
  if (parent.parent.header.StrapEntrySize >= 12) {
    u8 Flags5;            // Flags5
    u8 Mrs14MicronOffset; // Offset for Micron G5x memory internal core voltage
                          // (Bug 200266342)
  }
  s8 extra[parent.parent.header.StrapEntrySize + addressof(this) - $];
};
struct MEMORY_CLOCK_BASE_ENTRY_11 {
  u16 FreqMinimum; // Minimum frequency of Memory Clock usable with this entry
  u16 FreqMaximum; // Maximum frequency of Memory Clock usable with this entry
  u32 ScriptPointer;
  u8 Flags0; // Flags byte 0
  u32 FbpaConfig;
  u32 FbpaConfig1;
  u8 Flags1;             // Flags byte 1
  u8 RefMPLLSSFreqDelta; // Frequency Delta in 0.01% units, max of 2.55%
  // u8 Flags2;                  // Flags byte 2
  s8 clock_base_extra[parent.header.BaseEntrySize + addressof(this) - $];
  MEMORY_CLOCK_STRAP_ENTRY_11
  settings_indexed_by_strap_value[parent.header.StrapEntryCount];
};
struct MemoryClockTable {
  MEMORY_CLOCK_HEADER_1X header;
  try {
    MEMORY_CLOCK_BASE_ENTRY_11 frequency_ranges[header.EntryCount][[inline]];
  } catch {
    builtin::std::warning("memory_clock table parsing failed");
  }
};
struct BIT_DATA_CLOCK_PTRS_V2 {
  u32 PllInfoTablePtr; //<! Pointer to PLL Info Table
  if (parent.clock_token.data_version == 2) {
    u32 VBEModePCLKTablePtr;      //<! Pointer to VBE Mode PCLK Table table - VBIOS
                                  // only, unused by RM
    u32 ClocksTablePtr;           //<! Pointer to Clocks Table
    u32 ClockProgrammingTablePtr; //<! Pointer to Clock Programming Table
    u32 NAFLLTablePtr;            //<! Pointer to NAFLL Table
    u32 ADCTablePtr;              //<! Pointer to ADC Table
    u32 FreqControllerTablePtr;   //<! Pointer to Frequency Controller Table
    if (parent.clock_token.data_size >= 44) {
      u32 ClockEnumerationTablePtr; //<! Pointer to Clock Enumeration Table
      u32 ClockPropRegimeTablePtr;  //<! Pointer to Clock Propagation Regime
                                    // Table
      u32 ClockPropTopTablePtr;     //<! Pointer to Clock Propagation Topology Table
      u32 ClockPropTopRelTablePtr;  //<! Pointer to Clock Propagation Topology
                                    // Relationship Table
    }
  }
};
struct BIT_DATA_PERF_PTRS_V2 {
  u32 PerfTablePtr;         // Pointer to Performance Table
  u32 MemClockTablePtr;     // Pointer to Performance Memory Clock Table
  u32 MemTweakTablePtr;     // Pointer to Performance Memory Tweak Table
  u32 PowerControlTblPtr;   // Pointer to Power Control Table
  u32 ThermalControlTblPtr; // Pointer to Thermal Control Policy Table
  u32 ThermalDeviceTblPtr;  // Pointer to Thermal Device Table
  u32 ThermalCoolerTblPtr;  // Pointer to Thermal Control Coolers Table
  u32 SettingsScriptPtr;    // Pointer to Performance Settings Script
  u32 VoltageDescTblPtr;    // Pointer to Voltage Descriptor Table (VDT) or
                            //     Continuous Virtual Binning (CVB) Table.
  u32 SpbSensorParamTblPtr; // Pointer to Spb Sensor Parameters Table
  u32 PowerSensorsTblPtr;   // Pointer to Power Sensors Table
  u32 PowerCappingTblPtr;   // Pointer to Power Capping Table
  u32 PstateClkRangeTblPtr; // Pointer to P-state Clock Range Table
  u32 VoltageFreqTblPtr;    // Pointer to Voltage Frequency (VF) Table
  u32 VirtualPStateTblPtr;  // Pointer to Virtual P-state Table
  u32 PowerTopologyTblPtr;  // Pointer to Power Topology Table
  u32 PowerEquationTblPtr;  // Pointer to Power Equation Table
  if (parent.perf_token.data_size >= 156) {
    u32 PerfTestSpecTblPtr;       // Pointer to Performance Test Specifications Table
    u32 ThermalChannelTblPtr;     // Pointer to Thermal Channel Table
    u32 ThermalAdjustmentTblPtr;  // Pointer to Thermal Adjustment Table
    u32 ThermalPolicyTblPtr;      // Pointer to Thermal Policy Table
    u32 PstateMclkFreqTblPtr;     // Pointer to Pstate Mclk Frequency Table
    u32 FanCoolerTblPtr;          // Pointer to Fan Cooler Table
    u32 FanPolicyTblPtr;          // Pointer to Fan Policy Table
    u32 DIDT_TblPtr;              // Pointer to DI/DT Table
    u32 FanTestTblPtr;            // Pointer to Fan Test Table
    u32 VoltageRailTblPtr;        // Pointer to Voltage Rail Table
    u32 VoltageDeviceTblPtr;      // Pointer to Voltage Device Table
    u32 VoltagePolicyTblPtr;      // Pointer to Voltage Policy Table
    u32 LpwrIdxTablePtr;          // Pointer to LPWR Index Table
    u32 LpwrPcieTablePtr;         // Pointer to LPWR PCIe Table
    u32 LpwrPciePlatformTablePtr; // Pointer to LPWR PCIe-Platform Table
    u32 LpwrGrTablePtr;           // Pointer to LPWR GR Table
    u32 LpwrMsTablePtr;           // Pointer to LPWR MSCG Table
    u32 LpwrDiTablePtr;           // Pointer to LPWR DI Table
    u32 LpwrGc6TablePtr;          // Pointer to LPWR GC6 Table
    u32 LpwrPsiTablePtr;          // Pointer to LPWR PSI Table
    u32 ThermalMonitorTblPtr;     // Pointer to Thermal Monitor Table
    u32 OverclockingTblPtr;       // Pointer to Overclocking Table
  }
  if (parent.perf_token.data_size >= 224) {
    u32 LpwrNvlinkTablePtr;       // Pointer to LPWR Nvlink Table
    u32 PerfCfSensorTablePtr;     // Pointer to PERF_CF Sensor Table
    u32 PerfCfTopologyTablePtr;   // Pointer to PERF_CF Topology Table
    u32 PerfCfControllerTablePtr; // Pointer to PERF_CF Controller Table
    u32 PerfCfPolicyTablePtr;     // Pointer to PERF_CF Policy Table
    u32 IllumDeviceTablePtr;      // Pointer to ILLUM_DEVICE Table
    u32 IllumZoneTablePtr;        // Pointer to ILLUM_ZONE Table
    u32 PerfCfPwrModelTablePtr;   // Pointer to PERF_CF Pwr Model Table
    u32 LpwrApTablePtr;           // Pointer to LPWR AP Table
    u32 LpwrGcOffTablePtr;        // Pointer to LPWR GCOFF Table
    u32 NneVarsTablePtr;          // Pointer to NNE_VARS Table
    u32 NneLayersTablePtr;        // Pointer to NNE_LAYERS Table
    u32 NneDescsTablePtr;         // Pointer to NNE_DESCS Table
    u32 PerfCfPmSensorTablePtr;   // Pointer to PERF_CF PM Sensor Table
    u32 LpwrGrRgTablePtr;         // Pointer to LPWR GR-RG Table
    u32 LpwrEiTablePtr;           // Pointer to LPWR EI Table
    u32 FanArbiterTblPtr;         // Pointer to Fan Arbiter Table
  }
  if (parent.perf_token.data_size >= 232) {
    u32 FanAcousticsQualTblPtr;  // Pointer to Fan Acoustics Qual Table
    u32 ThermalPolicyOvrdTblPtr; // Pointer to Thermal Policy Override Table
  }
  if (parent.perf_token.data_size >= 236) {
    u32 LpwrDifrTablePtr; // Pointer to LPWR Difr Table
  }
};

enum UCodeApplicationID : u8 {
  NO = 0x0,
  PRE_OS = 0x1,
  GC6_DEVINIT_ENGINE = 0x2,
  GC6_DEVINIT_COMPACTION = 0x3,
  PRIMARY_DEVINIT_ENGINE = 0x4,
  FIRMWARE_SEC_LIC = 0x5,
  DEVINIT_RESERVED = 0x6,
  LS_UDE = 0x8,
  HULK = 0x9,
  DEVINIT_FMC = 0x13,
  POSTLTSSM = 0x14,
};

enum UCodeTargetID : u8 {
  NO = 0x0,
  PMU = 0x1,
  DPU = 0x2,
  FECS = 0x3,
  RESERVED = 0x4,
};

struct FALCON_UCODE_DESC_V1 {
  if (read_unsigned_le(addressof(this), 1) & 1) {
    u8 has_version_and_crypt;
    u8 version;
    u16 size;
  }
  u32 StoredSize;       // Size of stored data (Please read the wiki to find why
                        // StoredSize is here)
  u32 UncompressedSize; // Size of uncompressed ucode image
  u32 VirtualEntry;     // Code Entry Point
  u32 InterfaceOffset;  // DMEM address to App Interface Table
  u32 IMEMPhysBase;     // Physical Addr at which to load IMEM segment
  u32 IMEMLoadSize;     // Size of data to load into IMEM
  u32 IMEMVirtBase;     // Virtual Address of IMEM segment to load
  u32 IMEMSecBase;      // Virtual Address of secure IMEM segment
  u32 IMEMSecSize;      // Size of secure IMEM segment
  u32 DMEMOffset;       // Offset into store (uncompressed) image at
                        // which DMEM starts
  u32 DMEMPhysBase;     // Physical Address at which to load DMEM segment
  u32 DMEMLoadSize;     // Size of data to load into DMEM
  if (read_unsigned_le(addressof(this), 1) & 1) {
    u32 altIMEMLoadSize; // Size of code to load into IMEM
    u32 altDMEMLoadSize; // Size of data to load into DMEM
    padding[size + addressof(this) - $];
  }
  if (StoredSize == UncompressedSize &&
      (!(read_unsigned_le(addressof(this), 1) & 1) || read_unsigned_le(addressof(this) + 1, 1) == 2)) {
    u8 imem_pre_sec_segment[IMEMSecBase - IMEMVirtBase];
    u8 imem_sec_segment[IMEMSecSize];
    padding[DMEMOffset + addressof(imem_pre_sec_segment) - $];
    u8 dmem[DMEMLoadSize];
  }
};
struct FALCON_UCODE_TABLE_ENTRY_V1 {
  UCodeApplicationID ApplicationID; // ID of application implemented by ucode image
  UCodeTargetID TargetID;           // ID of Falcon Instance targeted by ucode image
  u32 DescPtr;                      // Pointer to Falcon Ucode Descriptor
  padding[parent.EntrySize + addressof(this) - $];
  if (DescPtr) {
    FALCON_UCODE_DESC_V1 desc @addressof(parent) + DescPtr - parent.parent.falcon_table_ptr;
  }
};

struct FALCON_UCODE_TABLE_HDR_V1 {
  u8 Version;     // Falcon Ucode table version (0x01)
  u8 HeaderSize;  // Size of Ucode Tbl Header in bytes(6)
  u8 EntrySize;   // Size of Ucode Tbl Entry in Bytes(6)
  u8 EntryCount;  // Number of table Entries
  u8 DescVersion; // Version of Falcon Ucode Descriptor
  u8 DescSize;    // Size of Falcon Ucode Descriptor
  padding[HeaderSize + addressof(this) - $];
  FALCON_UCODE_TABLE_ENTRY_V1 entries[EntryCount];
};

struct RomHeader1BitTableDetails : RomHeader1BitTableFoundTokens {
  BiosDataV2_Size33 biosdata @addressof(this) + bios_data_token.offset;
  if (sizeof(biosdata) < bios_data_token.data_size) {
    s8 biosdata_extra[bios_data_token.data_size - sizeof(biosdata)] @addressof(biosdata) + sizeof(biosdata);
  }
  BIT_DATA_CLOCK_PTRS_V2 clock @addressof(this) + clock_token.offset;
  if (sizeof(clock) < clock_token.data_size) {
    s8 clock_extra[clock_token.data_size - sizeof(clock)] @addressof(clock) + sizeof(clock);
  }
  BIT_DATA_NVINIT_PTRS_V1 nvinit @addressof(this) + nvinit_token.offset;
  if (sizeof(nvinit) < nvinit_token.data_size) {
    s8 nvinit_extra[nvinit_token.data_size - sizeof(nvinit)] @addressof(nvinit) + sizeof(nvinit);
  }
  BitMemoryOffsetsV2 memory @addressof(this) + memory_token.offset;
  if (sizeof(memory) < memory_token.data_size) {
    s8 memory_extra[memory_token.data_size - sizeof(memory)] @addressof(memory) + sizeof(memory);
  }
  BIT_DATA_PERF_PTRS_V2 perf @addressof(this) + perf_token.offset;
  if (sizeof(perf) < perf_token.data_size) {
    s8 perf_extra[perf_token.data_size - sizeof(perf)] @addressof(perf) + sizeof(perf);
  }
  if (addressof(strings_token) > 0) {
    BitTableString strings[strings_token.data_size / 3] @addressof(this) + strings_token.offset;
  }
  BitDataInternalUseV2_Size96 data_internal_use @addressof(this) + data_internal_use_token.offset;
  if (sizeof(data_internal_use) < data_internal_use_token.data_size) {
    s8 data_internal_use_extra[data_internal_use_token.data_size - sizeof(data_internal_use)]
        @addressof(data_internal_use) +
        sizeof(data_internal_use);
  }
  if (falcon_data_token.data_version == 2 && falcon_data_token.data_size == 4) {
    try {
      u32 falcon_table_ptr @addressof(this) + falcon_data_token.offset;
      FALCON_UCODE_TABLE_HDR_V1 falcon_ucode @adjust_skip_efi(
          addressof(this) + falcon_table_ptr, addressof(byte_last_pc_header), addressof(byte_pre_vn_header));
    } catch {
      builtin::std::warning("falcon_ucode table parsing failed");
    }
  }
  AddressMarkerByte section_base @addressof(this);
  AddressMarkerByte sect_strap_count @memory.MemStrapDataCount;
  try {
    u8 memstrap_translation[memory.MemStrapDataCount] @addressof(this) + memory.MemStrapXlatTblPtr;
    MEMORY_PART_INFO_HEADER_10 memory_part_info @addressof(this) + memory.MemPartInfoTblPtr;
  } catch {
    builtin::std::warning("memory extra tables parsing failed");
  }
  try {
    ScriptPointersArray init_scripts @addressof(section_base) + nvinit.InitScriptTablePtr;
  } catch {
    builtin::std::warning("init_scripts table parsing failed");
  }
};

fn section1_address(u32 address) {
  return adjust_skip_efi(addressof(section1_tables) + address, addressof(section1_tables.byte_last_pc_header),
                         addressof(section1_tables.byte_pre_vn_header));
  ;
};

RomHeader1BitTableDetails section1_tables @addressof(nvidia_vbios_rom_sections.rom_header1);

MemoryInfo mem_variants_by_strap @section1_address(section1_tables.memory.MemInfoTblPtr);
MemoryClockTable mem_clock_frequency_ranges @section1_address(section1_tables.perf.MemClockTablePtr);
MemoryTweakTable mem_tweak_timings @section1_address(section1_tables.perf.MemTweakTablePtr);
