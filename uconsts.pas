unit uInfo;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

const
  OS_SIGNATURE_COOKIE = $D7C82D1F;
  OS_ECC_256_SIGNATURE_COOKIE = $C6B71C0E;
  OS_ECC_512_SIGNATURE_COOKIE = $B5A60BFD;
  RSA_SIGNATURE_LENGTH = 128;
  ECC_521_SIGNATURE_LENGTH = 136;

type
  TSignature = packed record
    keyname: array [0..31] of char;
    keyID: cardinal;
    Len: cardinal;
    Sig: array of byte; // len
    BlockSize: cardinal;
    Ver: cardinal; // $10001
    Cookie: cardinal;
  end;

  TSignatures = array of TSignature;

  TSigsBlockv1 = packed record
    RSA_keyname: array [0..31] of char;
    RSA_keyID: cardinal;
    RSA_Len: cardinal;
    RSA_Sig: array[0..RSA_SIGNATURE_LENGTH - 1] of byte;
    RSA_BlockSize: cardinal;
    RSA_Ver: cardinal; // $10001
    RSA_Cookie: cardinal; // OS_SIGNATURE_COOKIE
  end;

  TSigsBlockv2 = packed record
    ECC_512_keyname: array [0..31] of char;
    ECC_512_keyID: cardinal;
    ECC_512_Len: cardinal;
    ECC_512_Sig: array[0..ECC_521_SIGNATURE_LENGTH - 1] of byte;
    ECC_512_BlockSize: cardinal;
    ECC_512_Ver: cardinal; // $10001
    ECC_512_Cookie: cardinal; // OS_ECC_512_SIGNATURE_COOKIE

    ECC_256_keyname: array [0..31] of char;
    ECC_256_keyID: cardinal;
    ECC_256_Len: cardinal;
    ECC_256_Sig: array[0..ECC_521_SIGNATURE_LENGTH - 1] of byte;
    ECC_256_BlockSize: cardinal;
    ECC_256_Ver: cardinal;
    ECC_256_Cookie: cardinal; // OS_ECC_256_SIGNATURE_COOKIE

    RSA_keyname: array [0..31] of char;
    RSA_keyID: cardinal;
    RSA_Len: cardinal;
    RSA_Sig: array[0..RSA_SIGNATURE_LENGTH - 1] of byte;
    RSA_BlockSize: cardinal;
    RSA_Ver: cardinal; // $10001
    RSA_Cookie: cardinal; // OS_SIGNATURE_COOKIE
  end;

type
  TLoadPtr = packed record
    LoadStart: longword;
    LoadEnd: longword;
    Reserved: array[0..19] of byte;
    Cookie: longword;
    LoadBase: longword;
    MetricsPtr: longword;
  end;

  THW_Override = packed record
    OS: dword;
    ID: dword;
  end;
  PHW_Override = ^THW_Override;

type
  THVW = record
    ID: byte;
    Val: byte;
  end;

  BR_Date = packed record
    Month: byte;
    Day: byte;
    Year: word;
  end;

  TBRMetrics = packed record
    version: longword;
    length: longword;
    BR_ver: longword;
    modelID: cardinal;
    HardwareName: array[0..63] of ansichar;
    BuildUser: array[0..15] of ansichar;
    BuildDate: array[0..15] of ansichar;
    BuildTime: array[0..15] of ansichar;
    Unk1: cardinal;
    SupportedOptions: cardinal;
    Unk5: cardinal;  // 00
    HWV_off: cardinal;
    Unk6: cardinal;  // 14
    Unk7: cardinal;  // FC
    Unk8: cardinal;  // 100
    Drivers: cardinal;
    LDRBlocks: cardinal;
    BootromSize: cardinal;
    Reserved2: cardinal; // 00
    Processor: cardinal;
    FlashID: cardinal;
    Unk3: cardinal;    // 04
    HWOSID: cardinal;
    BRID: cardinal;
    PersistAddr: cardinal;
    Unk9: cardinal;
    Unk10: cardinal;
    OldestMFI: BR_Date;
    OldestSFI: BR_Date;
    HVW: array [0..19] of THVW;
  end;
  PBRMetrics = ^TBRMetrics;


type
  TOSMetrics = packed record
    version: longword;
    length: longword;
    load_base_ptr: longword;
    load_end_ptr: longword;
    ram_end: longword;
    build_user: array[0..15] of ansichar;
    build_date: array[0..11] of ansichar;
    build_time: array[0..11] of ansichar;
    device_string: array[0..63] of ansichar;
    hardware_id: longword;
    os_version: longword;
  end;
  POSMetrics = ^TOSMetrics;

type
  TFlashInfo = packed record
    unk1: cardinal;  // 02
    VendorID: byte;
    DeviceID: byte;
    unk2: word;      // 00
    unk3: cardinal;  // 10000
    Blocks: cardinal;
    unk4: cardinal;  // 1000
    unk5: cardinal;  // 1000011
    Name: array[0..7] of char;// 0-terminated
    Serial: cardinal;
    unk6: cardinal;   // 91
    unk7: cardinal;   // 03
    unk8: cardinal;   // 00
    unk9: cardinal;   // 1000
    unk10: cardinal;  // 01
    unk11: cardinal;  // 00
    unk12: cardinal;  // 1000
    unk13: cardinal;  // 01
    unk14: cardinal;  // 1000
    unk15: cardinal;  // 01
    unk16: cardinal;  // 00
    unk17: cardinal;  // 1000
    unk18: cardinal;  // 6
    user: cardinal;
    unk19: array[0..91] of byte; // 00..00
    unk20: cardinal;  // 400000
  end;
  PFlashInfo = ^TFlashInfo;

  TDRAM_Info = packed record
    unk1: cardinal; // 2
    unk2: cardinal; // 3
    Size: cardinal; // bytes
    unk3: cardinal; // 0
    vendor: cardinal;
    revision: cardinal;
    unk4: array[0..11] of byte;
  end;
  PDRAM_Info = ^TDRAM_Info;

var
  dummy_signature: TBytes;

type
  TFourInts = array[0..3] of byte;
  PFourInts = ^TFourInts;

  TConverter = class
  public
    class function User2OS(const v: TFourInts): cardinal;
    class function OS2User(v: cardinal): TFourInts;
    class function Rom2OS(const v: TFourInts): cardinal;
    class function OS2Rom(v: cardinal): TFourInts;
  end;

function ExtractSignatures(Stream: TStream): TSignatures;

function VersionToString(Value: cardinal): string;
function StringToVersion(const s: string): cardinal;

function EMMCVendorByID(id: byte): string;
function DRAMVendorByID(id: byte): string;
function HWVtoString(val: THVW): string;
function DecodeBlocked(buf: TBytes): TStringList;

implementation

uses Math, StrUtils, uMisc;

const
  SUPPORTED_OS_LIST_SIZE = 10;

  STP_PROTOCOL_TYPE_FACTORY_OS = 2;
  STP_PROTOCOL_TYPE_RMA_OS = 8;
  STP_PROTOCOL_TYPE_SHIPPING_OS = 16;
  STP_PROTOCOL_TYPE_RAM_FACTORY_OS = 32;
  STP_PROTOCOL_TYPE_UNTRUSTED_OS = 64;

type

  TOSRangeAndType = packed record
    rangeStart: cardinal;
    rangeEnd: cardinal;
    osTypeBitMask: cardinal;
  end;
  POSRangeAndType = ^TOSRangeAndType;

function HWVtoString(val: THVW): string;
var
  Desc: string;
begin
  case val.id of
    $01: Desc := 'Board Revision';
    $02: Desc := 'CPU Version';
    $03: Desc := 'SW Compatibility';
    $04: Desc := 'POP Revision';
    $05: Desc := 'CPU Family';
    $07: Desc := 'Power Mgt Hardware';
    $0B: Desc := 'POP Security';
    $41: Desc := 'BSIS support';
    $45: Desc := 'WLAN FEM';
    $49: Desc := 'NFC';
    $4F: Desc := 'MFG DDR Traceability';
    $55: Desc := 'Keyboard Lang Var';
    $58: Desc := 'WLAN chip';
    else
      Desc := 'Unknown';
  end;

  (*
    Board Revision       0x01 - 0x0D
    CPU Version          0x02 - 0x10
    SW Compatibility     0x03 - 0x01
    POP Revision         0x04 - 0x03
    CPU Family           0x05 - 0x04
    Power Mgt Hardware   0x07 - 0x5C
    POP Security         0x0B - 0x01
    BSIS support         0x41 - 0x02
    WLAN FEM             0x45 - 0x0B
    NFC                  0x49 - 0x87
    MFG DDR Traceability 0x4F - 0x50
    Keyboard Lang Var    0x55 - 0x30
    WLAN chip            0x58 - 0x04
  *)
  Result := Format('%0:-21s0x%.2X - 0x%.2X', [Desc, val.ID, val.Val]);
end;


{ TConverter }

class function TConverter.User2OS(const v: TFourInts): cardinal;
begin
  Result := (v[0] and 255) shl 24 or (v[1] and 31) shl 19 or (v[2] shr 2 and 7) shl
    16 or (v[2] and 3) shl 13 or (v[3] and 8191);
end;

class function TConverter.OS2User(v: cardinal): TFourInts;
begin
  Result[0] := (v shr 24) and 255;
  Result[1] := (v shr 19) and 31;
  Result[2] := ((v shr 16) and 7) shl 2 or ((v shr 13) and 3);
  Result[3] := v and 8191;
end;

class function TConverter.Rom2OS(const v: TFourInts): cardinal;
begin
  Result := (v[0] and 255) shl 24 or (v[1] and 255) shl 16 or (v[2] and 1) shl 15 or (v[3] and 32767);
end;

class function TConverter.OS2Rom(v: cardinal): TFourInts;
begin
  Result[0] := (v shr 24) and 255;
  Result[1] := (v shr 16) and 255;
  Result[2] := (v shr 15) and 1;
  Result[3] := v and 32767;
end;


function ReadSignatureFromBuffer(const Buffer: TBytes; Offset: integer;
  BlockSize, Ver, Cookie: int64): TSignature;
var
  p: integer;
begin
  Result.BlockSize := BlockSize;
  Result.Ver := Ver;
  Result.Cookie := Cookie;

  p := Offset + 8;
  Move(Buffer[p], Result.keyname[0], SizeOf(Result.keyname));
  Inc(p, SizeOf(Result.keyname));

  Result.keyID := PDWord(@Buffer[p])^;
  Result.Len := PDWord(@Buffer[p + 4])^;

  if Result.Len > 0 then
  begin
    SetLength(Result.Sig, Result.Len);
    Move(Buffer[p + 8], Result.Sig[0], Result.Len);
  end
  else
    Result.Sig := nil;
end;

function ExtractSignatures(Stream: TStream): TSignatures;
const
  BufferSize = 40960; // 40KB
  xver = $10001;
  Cookies: array[0..2] of cardinal =
    (OS_SIGNATURE_COOKIE, OS_ECC_256_SIGNATURE_COOKIE, OS_ECC_512_SIGNATURE_COOKIE);
var
  Buffer: TBytes;
  savedp, p, size: int64;
  t1, t2, t3: cardinal;
  i, Count: integer;
  found: boolean;
begin
  savedp := Stream.Position;
  size := Stream.Size;

  if size < 12 then Exit(nil);

  // Read last 40KB into buffer
  SetLength(Buffer, Min(BufferSize, size));
  Stream.Position := size - Length(Buffer);
  Stream.ReadBuffer(Buffer[0], Length(Buffer));

  SetLength(Result, 4);
  Count := 0;
  found := False;
  p := size - 12;

  while (p >= size - Length(Buffer)) and (Count < 4) do
  begin
    i := p - (size - Length(Buffer));
    if i + 11 >= Length(Buffer) then
    begin
      Dec(p, 4);
      Continue;
    end;

    t1 := PDWord(@Buffer[i])^;
    t2 := PDWord(@Buffer[i + 4])^;
    t3 := PDWord(@Buffer[i + 8])^;

    if (t2 = xver) and (t1 > 0) and (t1 <= p) and ((t3 = Cookies[0]) or (t3 = Cookies[1]) or
      (t3 = Cookies[2])) then
    begin
      Dec(p, t1);
      i := p - (size - Length(Buffer));
      if (i >= 0) and (i + t1 <= Length(Buffer)) then
      begin
        Result[Count] := ReadSignatureFromBuffer(Buffer, i, t1, t2, t3);
        Inc(Count);
        found := True;
        Continue;
      end;
    end;

    if found then Break
    else
      Dec(p, 4);
  end;

  SetLength(Result, Count);
  Stream.Position := savedp;
end;

procedure GenDummySig(var Buf: TBytes);
begin
  if Length(Buf) <> 560 then
    SetLength(Buf, 560);
  // Fill buffer with $FF
  FillChar(Buf[0], 560, $FF);

  // Direct assignments (fastest for small number of patches)
  PLongWord(@Buf[$24])^ := $00000088;
  PLongWord(@Buf[$B0])^ := $000000BC;
  PLongWord(@Buf[$B4])^ := $00010001;
  PLongWord(@Buf[$B8])^ := $B5A60BFD;
  PLongWord(@Buf[$E0])^ := $00000088;
  PLongWord(@Buf[$16C])^ := $000000BC;
  PLongWord(@Buf[$170])^ := $00010001;
  PLongWord(@Buf[$174])^ := $C6B71C0E;
  PLongWord(@Buf[$180])^ := $00000080;
  PLongWord(@Buf[$220])^ := $000000B4;
  PLongWord(@Buf[$224])^ := $00010001;
  PLongWord(@Buf[$228])^ := $D7C82D1F;
end;

function EncodeVersion(major, minor, maint, build: word; isProd: boolean): cardinal;
begin
  Result := 0;
  Result := Result or (major and $FF) shl 24;
  Result := Result or (minor and $1F) shl 19;
  Result := Result or ((maint shr 2) and $07) shl 16;
  if isProd then
    Result := Result or (1 shl 15);
  Result := Result or (maint and $03) shl 13;
  Result := Result or (build and $1FFF);
end;

procedure DecodeVersion(Value: cardinal; out major, minor, maint, build: word; out isProd: boolean);
var
  maintMSB, maintLSB: word;
begin
  major := (Value shr 24) and $FF;
  minor := (Value shr 19) and $1F;
  maintMSB := (Value shr 16) and $07;
  maintLSB := (Value shr 13) and $03;
  maint := (maintMSB shl 2) or maintLSB;
  isProd := ((Value shr 15) and 1) = 1;
  build := Value and $1FFF;
end;

function VersionToString(Value: cardinal): string;
var
  major, minor, maint, build: word;
  isProd: boolean;
begin
  DecodeVersion(Value, major, minor, maint, build, isProd);
  Result := Format('%d.%d.%d.%d %s', [major, minor, maint, build, IfThen(isProd, 'PROD', 'DEV')]);
end;

function StringToVersion(const s: string): cardinal;
var
  parts: TStringArray;
  major, minor, maint, build: word;
  isProd: boolean;
begin
  parts := SplitString(s, '.');
  if Length(parts) < 4 then
    raise Exception.Create('Invalid version string');

  major := StrToInt(parts[0]);
  minor := StrToInt(parts[1]);
  maint := StrToInt(parts[2]);

  // parts[3] may be like "1281 DEV" or "1281 PROD"
  if Pos(' ', parts[3]) > 0 then
  begin
    build := StrToInt(Copy(parts[3], 1, Pos(' ', parts[3]) - 1));
    isProd := Trim(Copy(parts[3], Pos(' ', parts[3]) + 1, 10)) = 'PROD';
  end
  else
  begin
    build := StrToInt(parts[3]);
    isProd := False;
  end;

  Result := EncodeVersion(major, minor, maint, build, isProd);
end;


function DecodeBlocked(buf: TBytes): TStringList;

  function DecodeOsType(ostype: cardinal): string;
  begin
    Result := '';
    case (ostype and (STP_PROTOCOL_TYPE_UNTRUSTED_OS - 1)) of
      STP_PROTOCOL_TYPE_FACTORY_OS:
        Result := 'SFI';
      STP_PROTOCOL_TYPE_SHIPPING_OS:
        Result := 'MFI';
      STP_PROTOCOL_TYPE_RAM_FACTORY_OS:
        Result := 'RFA';
      STP_PROTOCOL_TYPE_RMA_OS:
        Result := 'RMA';
      else
        Result := 'Unsupported';
    end;
    if (ostype and STP_PROTOCOL_TYPE_UNTRUSTED_OS) = STP_PROTOCOL_TYPE_UNTRUSTED_OS then
      Result := Result + ',Untrusted';
  end;

var
  i, c: integer;
begin
  if length(buf) = 0 then Exit(nil);
  Result := TStringList.Create;
  c := PInteger(@buf[0])^;
  for i := 0 to c - 1 do
  begin
    with POSRangeAndType(@buf[4 + i * SizeOf(TOSRangeAndType)])^ do
    begin
      Result.Add(Format('   range:              From %s To %s',
        [VersionToString(rangeStart), VersionToString(rangeEnd)]));
      Result.Add(Format('    type:              %s', [DecodeOsType(osTypeBitMask)]));
    end;
  end;
end;

function DRAMVendorByID(id: byte): string;
begin
  case id of
    1: Result := 'Samsung';
    2: Result := 'Qimonda';
    3: Result := 'Elpida';
    4: Result := 'Etron';
    5: Result := 'Nanya';
    6: Result := 'Hynix';
    7: Result := 'Mosel';
    8: Result := 'Winbond';
    9: Result := 'ESMT';
    11: Result := 'Spansion';
    12: Result := 'SST';
    13: Result := 'ZMOS';
    14: Result := 'Intel';
    $FE: Result := 'Numonyx';
    $FF: Result := 'Micron';
    else
      Result := 'Unknown';
  end;
end;

function EMMCVendorByID(id: byte): string;
begin
  case id of
    $45: Result := 'SanDisk (4.3)';
    2: Result := 'SanDisk (4.41)';
    $15: Result := 'Samsung';
    $11: Result := 'Toshiba';
    $FE: Result := 'Numonyx';
    $13: Result := 'Micron';
    $90: Result := 'Hynix';
    else
      Result := 'Unknown';
  end;
end;


initialization
  GenDummySig(dummy_signature);

end.
