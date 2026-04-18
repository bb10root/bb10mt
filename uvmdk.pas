unit uVMDK;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  SECTOR_SIZE = 512;
  VMDK_MAGIC = $564D444B; // 'KDMV'
  PT_EXTENDED1 = $05;
  PT_EXTENDED2 = $0F;
  PT_EXTENDED3 = $85;

type
  TVMDKHeader = packed record
    MagicNumber: longword;      // 0x564D444B 'KDMV'
    Version: longword;          // usually 1
    Flags: longword;
    Capacity: QWord;            // sectors (512B)
    GrainSize: QWord;           // sectors per grain
    DescriptorOffset: QWord;    // sector
    DescriptorSize: QWord;      // sector
    NumGTEsPerGT: longword;     // entries per Grain Table
    RgdOffset: QWord;           // sector (redundant GD)
    GdOffset: QWord;            // sector (primary GD)
    Overhead: QWord;            // total metadata sectors
    UncleanShutdown: longword;
    SingleEndLineChar: byte;
    NonEndLineChar: byte;
    DoubleEndLineChar1: byte;
    DoubleEndLineChar2: byte;
    CompressAlgorithm: word;    // 0=none for monolithicSparse
  end;

  TVMDKKind = (vkUnknown, vkFlat, vkSparse);

  TMBRPartitionEntry = packed record
    BootIndicator: byte;
    StartingCHS: array[0..2] of byte;
    PartitionType: byte;
    EndingCHS: array[0..2] of byte;
    StartingLBA: longword;
    SizeInLBA: longword;
  end;

  TGPTHeader = packed record
    Signature: array[0..7] of ansichar; // 'EFI PART'
    Revision: longword;
    HeaderSize: longword;
    HeaderCRC32: longword;
    Reserved: longword;
    CurrentLBA: QWord;
    BackupLBA: QWord;
    FirstUsableLBA: QWord;
    LastUsableLBA: QWord;
    DiskGUID: array[0..15] of byte;
    PartitionEntriesLBA: QWord;
    NumberOfPartitionEntries: longword;
    SizeOfPartitionEntry: longword;
    PartitionEntriesCRC32: longword;
    // rest ignored
  end;

  TGPTEntry = packed record
    PartitionTypeGUID: array[0..15] of byte;
    UniquePartitionGUID: array[0..15] of byte;
    FirstLBA: QWord;
    LastLBA: QWord;
    Attributes: QWord;
    NameUTF16: array[0..71] of word; // 72 UTF-16LE chars
  end;

  TPartitionInfo = record
    Index: integer;       // 1-based
    Scheme: string;       // 'MBR','MBR-LOG','GPT'
    TypeHex: string;      // '0x83' or GUID
    StartLBA: QWord;
    SizeLBA: QWord;
    NameStr: string;      // GPT name if any
  end;

  TPartitionArray = array of TPartitionInfo;

  { Mapper РґР»СЏ С‡РёС‚Р°РЅРЅСЏ СЃРµРєС‚РѕСЂС–РІ Р· VMDK (flat Р°Р±Рѕ sparse) }
  TVMDKReader = class
  private
    FStream: TStream;
    FKind: TVMDKKind;
    FHeader: TVMDKHeader;
    FCapacity: QWord;     // sectors
    FGrainSize: QWord;    // sectors per grain
    FNumGTEsPerGT: longword;
    FGD: array of longword;     // Grain Directory (sector offsets of GT)
    FGTCache_Idx: longint;      // last GT index cached
    FGTCache: array of longword; // cached GT entries (sector offsets of grains)
    function LoadSparseHeader: boolean;
    function LoadGD: boolean;
    function LoadGT(Index: longint): boolean;
    function MapLBAtoFileOffset(LBA: QWord; out FileOffset: QWord): boolean;
  public
    constructor Create(AStream: TStream);
    function Kind: TVMDKKind;
    function CapacitySectors: QWord;
    function ReadSectors(LBA: QWord; Count: QWord; Dest: Pointer): boolean;
    function WriteSectors(LBA: QWord; Count: QWord; const Src: Pointer): boolean;
  end;


procedure ListPartitions(reader: TVMDKReader; var parts: TPartitionArray);
function ExtractPartition(reader: TVMDKReader; const p: TPartitionInfo; outStream: TStream): boolean;
function ExtractPartition(reader: TVMDKReader; const p: TPartitionInfo; const outPath: string): boolean;
function WritePartition(reader: TVMDKReader; const p: TPartitionInfo; inStream: TStream): boolean;
procedure PrintPartitions(const parts: TPartitionArray);

implementation

{ ==== Utils ==== }

function Hex2(a: byte): string;
begin
  Result := IntToHex(a, 2);
end;

function GUIDToStringLE(const G: array of byte): string;
var
  s: string;
begin
  // GPT GUID fields: 4-2-2-2-6 with first three little-endian
  s := IntToHex(PDWord(@G[0])^, 8) + '-' + IntToHex(PWord(@G[4])^, 4) + '-' +
    IntToHex(PWord(@G[6])^, 4) + '-' + Hex2(G[8]) + Hex2(G[9]) + '-' + Hex2(G[10]) +
    Hex2(G[11]) + Hex2(G[12]) + Hex2(G[13]) + Hex2(G[14]) + Hex2(G[15]);
  // reverse endianness for first three parts
  Result :=
    Copy(s, 7, 2) + Copy(s, 5, 2) + Copy(s, 3, 2) + Copy(s, 1, 2) + '-' + Copy(s, 14, 2) +
    Copy(s, 12, 2) + '-' + Copy(s, 19, 2) + Copy(s, 17, 2) + '-' + Copy(s, 22, 4) + '-' + Copy(s, 27, 12);
end;

function UTF16ToUTF8Trim(const W: array of word): string;
var
  i: integer;
  len: integer;
  s: unicodestring;
begin
  len := Length(W);
  SetLength(s, len);
  for i := 0 to len - 1 do
    s[i + 1] := widechar(W[i]);
  // trim trailing #0
  while (Length(s) > 0) and (s[Length(s)] = #0) do
    Delete(s, Length(s), 1);
  Result := UTF8Encode(s);
end;

{ ==== TVMDKReader ==== }

constructor TVMDKReader.Create(AStream: TStream);
var
  sig: longword;
  pos0: int64;
begin
  inherited Create;
  FStream := AStream;
  FKind := vkUnknown;
  FCapacity := 0;
  FGrainSize := 0;
  FNumGTEsPerGT := 0;
  SetLength(FGD, 0);
  SetLength(FGTCache, 0);
  FGTCache_Idx := -1;

  pos0 := FStream.Position;
  FStream.Position := 0;
  if FStream.Size >= SizeOf(TVMDKHeader) then
  begin
    FStream.ReadBuffer(FHeader, SizeOf(TVMDKHeader));
    if FHeader.MagicNumber = VMDK_MAGIC then
    begin
      FKind := vkSparse;
      FCapacity := FHeader.Capacity;
      FGrainSize := FHeader.GrainSize;
      FNumGTEsPerGT := FHeader.NumGTEsPerGT;
      // preload GD
      if not LoadGD then
        FKind := vkUnknown;
    end
    else
    begin
      // fallback: treat as flat/raw image (no sparse header)
      FKind := vkFlat;
      // capacity unknown -> derive from size
      FCapacity := QWord(FStream.Size div SECTOR_SIZE);
    end;
  end
  else
    FKind := vkFlat;

  FStream.Position := pos0;
end;

function TVMDKReader.Kind: TVMDKKind;
begin
  Result := FKind;
end;

function TVMDKReader.CapacitySectors: QWord;
begin
  Result := FCapacity;
end;

function TVMDKReader.LoadSparseHeader: boolean;
begin
  // already read in constructor; keep for symmetry
  Result := (FHeader.MagicNumber = VMDK_MAGIC);
end;

function TVMDKReader.LoadGD: boolean;
var
  gdBytes: QWord;
  entries: QWord;
begin
  Result := False;
  if FHeader.GdOffset = 0 then Exit;
  // entries = ceil(ceil(capacity/grainSize) / NumGTEsPerGT)
  entries := (FCapacity + FGrainSize - 1) div FGrainSize;
  entries := (entries + FNumGTEsPerGT - 1) div FNumGTEsPerGT;
  if entries = 0 then entries := 1;

  SetLength(FGD, entries);
  FStream.Position := FHeader.GdOffset * SECTOR_SIZE;
  gdBytes := entries * SizeOf(longword);
  FStream.ReadBuffer(FGD[0], gdBytes);
  Result := True;
end;

function TVMDKReader.LoadGT(Index: longint): boolean;
var
  gtSector: QWord;
  Count: QWord;
begin
  Result := False;
  if (Index < 0) or (Index >= Length(FGD)) then Exit;
  gtSector := FGD[Index];
  if gtSector = 0 then Exit; // no table -> unmapped
  SetLength(FGTCache, FNumGTEsPerGT);
  Count := QWord(FNumGTEsPerGT) * SizeOf(longword);
  FStream.Position := gtSector * SECTOR_SIZE;
  FStream.ReadBuffer(FGTCache[0], Count);
  FGTCache_Idx := Index;
  Result := True;
end;

function TVMDKReader.MapLBAtoFileOffset(LBA: QWord; out FileOffset: QWord): boolean;
var
  grainIndex: QWord;
  gtIdx: longint;
  gteIdx: longint;
  grainSector: longword;
  offsetInGrainSectors: QWord;
begin
  Result := False;
  FileOffset := 0;

  if FKind = vkFlat then
  begin
    FileOffset := LBA * SECTOR_SIZE;
    Result := True;
    Exit;
  end;

  if (FKind <> vkSparse) or (FGrainSize = 0) or (FNumGTEsPerGT = 0) then Exit;

  grainIndex := LBA div FGrainSize;
  offsetInGrainSectors := LBA mod FGrainSize;

  gtIdx := longint(grainIndex div FNumGTEsPerGT);
  gteIdx := longint(grainIndex mod FNumGTEsPerGT);

  if (FGTCache_Idx <> gtIdx) then
    if not LoadGT(gtIdx) then Exit;

  grainSector := FGTCache[gteIdx];

  if grainSector = 0 then
  begin
    // РіСЂР°РЅСѓР»Р° РЅРµ РІРёРґС–Р»РµРЅР° => РїСЂРѕРїСѓСЃРєР°С”РјРѕ Р·Р°РїРёСЃ
    FileOffset := 0;
    Exit;  // Result = False
  end;

  FileOffset := (QWord(grainSector) + offsetInGrainSectors) * SECTOR_SIZE;
  Result := True;
end;

function TVMDKReader.ReadSectors(LBA: QWord; Count: QWord; Dest: Pointer): boolean;
var
  left: QWord;
  ptr: pbyte;
  lbaCur: QWord;
  fileOff: QWord;
  maxPerGrain: QWord;
  granRemain: QWord;
  chunk: QWord;
begin
  Result := False;
  left := Count;
  ptr := Dest;
  lbaCur := LBA;

  while left > 0 do
  begin
    if FKind = vkSparse then
    begin
      maxPerGrain := FGrainSize;
      granRemain := maxPerGrain - (lbaCur mod maxPerGrain);
      if granRemain = 0 then granRemain := maxPerGrain;
      if left < granRemain then chunk := left
      else
        chunk := granRemain;

      if MapLBAtoFileOffset(lbaCur, fileOff) then
      begin
        // С–СЃРЅСѓСЋС‡Р° РіСЂР°РЅСѓР»Р°
        FStream.Position := fileOff;
        FStream.ReadBuffer(ptr^, chunk * SECTOR_SIZE);
      end
      else
      begin
        // unallocated => zeros
        FillChar(ptr^, chunk * SECTOR_SIZE, 0);
      end;

      Dec(left, chunk);
      Inc(lbaCur, chunk);
      Inc(ptr, chunk * SECTOR_SIZE);
    end
    else
    begin
      // flat/raw: С‡РёС‚Р°С”РјРѕ РІСЃРµ РѕРґСЂР°Р·Сѓ
      if not MapLBAtoFileOffset(lbaCur, fileOff) then Exit;
      FStream.Position := fileOff;
      FStream.ReadBuffer(ptr^, left * SECTOR_SIZE);
      left := 0;
    end;
  end;

  Result := True;
end;

function TVMDKReader.WriteSectors(LBA: QWord; Count: QWord; const Src: Pointer): boolean;
var
  left: QWord;
  ptr: pbyte;
  lbaCur: QWord;
  fileOff: QWord;
  maxPerGrain: QWord;
  granRemain: QWord;
  chunk: QWord;
begin
  Result := False;
  left := Count;
  ptr := Src;
  lbaCur := LBA;
  maxPerGrain := FGrainSize;

  while left > 0 do
  begin
    // Р РѕР·СЂР°С…СѓРЅРѕРє Р·Р°Р»РёС€РєСѓ СЃРµРєС‚РѕСЂС–РІ РґРѕ РєС–РЅС†СЏ РіСЂР°РЅСѓР»Рё
    granRemain := maxPerGrain - (lbaCur mod maxPerGrain);
    if granRemain = 0 then granRemain := maxPerGrain;
    if left < granRemain then chunk := left
    else
      chunk := granRemain;

    if FKind = vkSparse then
    begin
      // РЁСѓРєР°С”РјРѕ РїРµСЂС€РёР№ Р±Р»РѕРє РЅР°СЏРІРЅРёС… РіСЂР°РЅСѓР»
      while (chunk > 0) and (not MapLBAtoFileOffset(lbaCur, fileOff)) do
      begin
        // РџСЂРѕРїСѓСЃРєР°С”РјРѕ РІС–РґСЃСѓС‚РЅСЋ РіСЂР°РЅСѓР»Сѓ
        Dec(chunk);
        Inc(lbaCur);
        Inc(ptr, SECTOR_SIZE);
        Dec(left);
        granRemain := granRemain - 1;
        if granRemain = 0 then
        begin
          granRemain := maxPerGrain;
          if left < granRemain then chunk := left
          else
            chunk := granRemain;
        end;
      end;

      // Р—Р°РїРёСЃСѓС”РјРѕ Р±Р»РѕРє РЅР°СЏРІРЅРѕС— РіСЂР°РЅСѓР»Рё
      if chunk > 0 then
      begin
        FStream.Position := fileOff;
        FStream.WriteBuffer(ptr^, chunk * SECTOR_SIZE);
        Dec(left, chunk);
        Inc(lbaCur, chunk);
        Inc(ptr, chunk * SECTOR_SIZE);
      end;
    end
    else
    begin
      // flat/raw: Р·Р°РїРёСЃСѓС”РјРѕ РІСЃРµ РѕРґСЂР°Р·Сѓ
      if not MapLBAtoFileOffset(lbaCur, fileOff) then Exit;
      FStream.Position := fileOff;
      FStream.WriteBuffer(ptr^, left * SECTOR_SIZE);
      left := 0;
    end;
  end;

  Result := True;
end;


{ ==== РџР°СЂСЃРёРЅРі MBR/GPT ==== }

procedure AddPartition(var Arr: TPartitionArray; const P: TPartitionInfo);
var
  n: integer;
begin
  n := Length(Arr);
  SetLength(Arr, n + 1);
  Arr[n] := P;
end;

procedure ParseMBR(reader: TVMDKReader; lbaStart: QWord; baseExtended: QWord;
  isLogical: boolean; var outArr: TPartitionArray);
var
  buf: array[0..SECTOR_SIZE - 1] of byte;
  i: integer;
  entry: TMBRPartitionEntry;
  p: TPartitionInfo;
  ebrNextRel: QWord;
  partStartAbs: QWord;
  partSize: QWord;
  isExt: boolean;
begin
  if not reader.ReadSectors(lbaStart, 1, @buf[0]) then Exit;
  if (buf[$1FE] <> $55) or (buf[$1FF] <> $AA) then Exit;

  ebrNextRel := 0;

  for i := 0 to 3 do
  begin
    Move(buf[$1BE + i * 16], entry, SizeOf(entry));
    if entry.PartitionType = 0 then Continue;

    isExt := (entry.PartitionType = PT_EXTENDED1) or (entry.PartitionType = PT_EXTENDED2) or
      (entry.PartitionType = PT_EXTENDED3);

    if (not isLogical) and isExt then
    begin
      // Р¦Рµ extended РєРѕРЅС‚РµР№РЅРµСЂ Сѓ РіРѕР»РѕРІРЅРѕРјСѓ MBR
      baseExtended := QWord(entry.StartingLBA);
      // Р—Р°РїСѓСЃС‚РёРјРѕ Р»Р°РЅС†СЋРі EBR
      ParseMBR(reader, baseExtended, baseExtended, True, outArr);
    end
    else if isLogical then
    begin
      // РЈ EBR РїРµСЂС€РёР№ Р·Р°РїРёСЃ вЂ” Р»РѕРіС–С‡РЅРёР№ СЂРѕР·РґС–Р», РґСЂСѓРіРёР№ вЂ” РїРѕСЃРёР»Р°РЅРЅСЏ РЅР° РЅР°СЃС‚СѓРїРЅРёР№ EBR
      if i = 0 then
      begin
        partStartAbs := baseExtended + QWord(entry.StartingLBA);
        partSize := QWord(entry.SizeInLBA);

        FillChar(p, SizeOf(p), 0);
        p.Index := 0; // С–РЅРґРµРєСЃ РїСЂРѕСЃС‚Р°РІРёРјРѕ РїС–Р·РЅС–С€Рµ РїСЂРё РґСЂСѓС†С–
        p.Scheme := 'MBR-LOG';
        p.TypeHex := '0x' + IntToHex(entry.PartitionType, 2);
        p.StartLBA := partStartAbs;
        p.SizeLBA := partSize;
        p.NameStr := '';
        AddPartition(outArr, p);
      end
      else if i = 1 then
      begin
        ebrNextRel := QWord(entry.StartingLBA);
      end;
    end
    else
    begin
      // Primary
      partStartAbs := QWord(entry.StartingLBA);
      partSize := QWord(entry.SizeInLBA);

      FillChar(p, SizeOf(p), 0);
      p.Index := 0;
      p.Scheme := 'MBR';
      p.TypeHex := '0x' + IntToHex(entry.PartitionType, 2);
      p.StartLBA := partStartAbs;
      p.SizeLBA := partSize;
      p.NameStr := '';
      AddPartition(outArr, p);
    end;
  end;

  // РїРµСЂРµС…С–Рґ РґРѕ РЅР°СЃС‚СѓРїРЅРѕРіРѕ EBR
  if isLogical and (ebrNextRel <> 0) then
    ParseMBR(reader, baseExtended + ebrNextRel, baseExtended, True, outArr);
end;

procedure ParseGPT(reader: TVMDKReader; var outArr: TPartitionArray);
var
  hdr: TGPTHeader;
  ok: boolean;
  buf: array[0..SECTOR_SIZE - 1] of byte;
  entriesPerSector: longword;
  totalEntries: longword;
  i: longword;
  entryBuf: array of byte;
  gptEntry: TGPTEntry;
  sectorLBA, posLBA: QWord;
  p: TPartitionInfo;
  nameStr: string;
  absByte: QWord;
  inSectorOff: longword;
  buf2: array[0..SECTOR_SIZE - 1] of byte;
  firstPart, secondPart: longword;
begin
  // LBA1 вЂ” GPT Header
  ok := reader.ReadSectors(1, 1, @buf[0]);
  if not ok then Exit;
  Move(buf[0], hdr, SizeOf(hdr));

  if (hdr.Signature[0] <> 'E') or (hdr.Signature[1] <> 'F') or (hdr.Signature[2] <> 'I') or
    (hdr.Signature[3] <> ' ') or (hdr.Signature[4] <> 'P') or (hdr.Signature[5] <> 'A') or
    (hdr.Signature[6] <> 'R') or (hdr.Signature[7] <> 'T') then
    Exit;

  totalEntries := hdr.NumberOfPartitionEntries;
  if totalEntries = 0 then Exit;

  // Р·С‡РёС‚СѓС”РјРѕ РІСЃС– entries РїРѕСЃРµРєС‚РѕСЂРЅРѕ
  SetLength(entryBuf, hdr.SizeOfPartitionEntry);
  posLBA := hdr.PartitionEntriesLBA;

  for i := 0 to totalEntries - 1 do
  begin
    // РєРѕР¶РµРЅ Р·Р°РїРёСЃ РјРѕР¶Рµ РїРµСЂРµС‚РёРЅР°С‚Рё СЃРµРєС‚РѕСЂРё; С‡РёС‚Р°С”РјРѕ С‚РѕС‡РЅРёР№ СЃРµРєС‚РѕСЂ РґР»СЏ С†СЊРѕРіРѕ Р·Р°РїРёСЃСѓ
    // Р°Р»Рµ РїСЂРѕСЃС‚С–С€Рµ: С‡РёС‚Р°С”РјРѕ РєРѕР¶РµРЅ Р·Р°РїРёСЃ РѕРєСЂРµРјРѕ:
    // entryN Р·РЅР°С…РѕРґРёС‚СЊСЃСЏ Р·Р° Р°РґСЂРµСЃРѕСЋ posLBA + (i * Size)/512
    // Р·СЃСѓРІ Сѓ СЃРµРєС‚РѕСЂС–:
    // Р”Р»СЏ РїСЂРѕСЃС‚РѕС‚Рё С‡РёС‚Р°С”РјРѕ СЃРµРєС‚РѕСЂ, РґРµ Р»РµР¶РёС‚СЊ РїРѕС‡Р°С‚РѕРє Р·Р°РїРёСЃСѓ

    absByte := posLBA * SECTOR_SIZE + QWord(i) * QWord(hdr.SizeOfPartitionEntry);
    sectorLBA := absByte div SECTOR_SIZE;
    inSectorOff := longword(absByte mod SECTOR_SIZE);

    ok := reader.ReadSectors(sectorLBA, 1, @buf[0]);
    if not ok then Exit;

    if inSectorOff + hdr.SizeOfPartitionEntry <= SECTOR_SIZE then
      Move(buf[inSectorOff], gptEntry, SizeOf(TGPTEntry))
    else
    begin
      // Р·Р°РїРёСЃ РїРµСЂРµС‚РёРЅР°С” СЃРµРєС‚РѕСЂ вЂ” РґРѕС‡РёС‚СѓС”РјРѕ РЅР°СЃС‚СѓРїРЅРёР№
      firstPart := SECTOR_SIZE - inSectorOff;
      secondPart := hdr.SizeOfPartitionEntry - firstPart;
      Move(buf[inSectorOff], pbyte(@gptEntry)^, firstPart);
      ok := reader.ReadSectors(sectorLBA + 1, 1, @buf2[0]);
      if not ok then Exit;
      Move(buf2[0], pbyte(@gptEntry)[firstPart], secondPart);
    end;

    // РїРѕСЂРѕР¶РЅС–Р№ Р·Р°РїРёСЃ?
    if (gptEntry.PartitionTypeGUID[0] = 0) and (gptEntry.PartitionTypeGUID[1] = 0) then
      Continue;

    nameStr := UTF16ToUTF8Trim(gptEntry.NameUTF16);

    FillChar(p, SizeOf(p), 0);
    p.Index := 0;
    p.Scheme := 'GPT';
    p.TypeHex := GUIDToStringLE(gptEntry.PartitionTypeGUID);
    p.StartLBA := gptEntry.FirstLBA;
    p.SizeLBA := gptEntry.LastLBA - gptEntry.FirstLBA + 1;
    p.NameStr := nameStr;
    AddPartition(outArr, p);
  end;
end;

procedure ListPartitions(reader: TVMDKReader; var parts: TPartitionArray);
var
  mbrBuf: array[0..SECTOR_SIZE - 1] of byte;
  isMBR: boolean;
  i: integer;
begin
  SetLength(parts, 0);
  isMBR := False;

  if reader.ReadSectors(0, 1, @mbrBuf[0]) then
  begin
    if (mbrBuf[$1FE] = $55) and (mbrBuf[$1FF] = $AA) then
    begin
      isMBR := True;
      ParseMBR(reader, 0, 0, False, parts);
    end;
  end;

  // РџРµСЂРµРІС–СЂРёРјРѕ GPT (protective MBR + GPT)
  ParseGPT(reader, parts);

  // РџСЂРѕРЅСѓРјРµСЂСѓС”РјРѕ С–РЅРґРµРєСЃРё
  for i := 0 to Length(parts) - 1 do
    parts[i].Index := i + 1;
end;

function ExtractPartition(reader: TVMDKReader; const p: TPartitionInfo; outStream: TStream): boolean;
var
  buf: array of byte;
  total: QWord;
  doneSectors: QWord;
  chunkSectors: QWord;
  toDo: QWord;
  readOK: boolean;
begin
  Result := False;
  SetLength(buf, 0);

  try
    total := p.SizeLBA;
    doneSectors := 0;
    chunkSectors := 2048; // 2048*512 = 1 MiB Р±СѓС„РµСЂ
    SetLength(buf, chunkSectors * SECTOR_SIZE);

    while doneSectors < total do
    begin
      toDo := chunkSectors;
      if toDo > (total - doneSectors) then
        toDo := total - doneSectors;

      readOK := reader.ReadSectors(p.StartLBA + doneSectors, toDo, @buf[0]);
      if not readOK then Exit;

      outStream.WriteBuffer(buf[0], toDo * SECTOR_SIZE);
      Inc(doneSectors, toDo);
    end;

    Result := True;
  finally
    SetLength(buf, 0);
  end;
end;

function WritePartition(reader: TVMDKReader; const p: TPartitionInfo; inStream: TStream): boolean;
var
  buf: array of byte;
  total: QWord;
  doneSectors: QWord;
  chunkSectors: QWord;
  toDo: QWord;
  writeOK: boolean;
begin
  Result := False;
  SetLength(buf, 0);

  try
    total := p.SizeLBA;
    doneSectors := 0;
    chunkSectors := 2048; // 2048*512 = 1 MiB Р±СѓС„РµСЂ
    SetLength(buf, chunkSectors * SECTOR_SIZE);

    while doneSectors < total do
    begin
      toDo := chunkSectors;
      if toDo > (total - doneSectors) then
        toDo := total - doneSectors;

      inStream.ReadBuffer(buf[0], toDo * SECTOR_SIZE);

      writeOK := reader.WriteSectors(p.StartLBA + doneSectors, toDo, @buf[0]);
      if not writeOK then Exit;

      Inc(doneSectors, toDo);
    end;

    Result := True;
  finally
    SetLength(buf, 0);
  end;
end;


function ExtractPartition(reader: TVMDKReader; const p: TPartitionInfo; const outPath: string): boolean;
var
  outStream: TFileStream;
begin
  Result := False;
  outStream := TFileStream.Create(outPath, fmCreate);
  try
    Result := ExtractPartition(reader, p, outStream);
  finally
    FreeAndNil(outStream);
  end;
end;


procedure PrintPartitions(const parts: TPartitionArray);
var
  i: integer;
begin
  if Length(parts) = 0 then
  begin
    Writeln('No partitions found.');
    Exit;
  end;

  Writeln('#  Scheme     Type                     Start LBA       Size LBA         Size (bytes)     Name');
  for i := 0 to Length(parts) - 1 do
  begin
    Writeln(Format('%-3d%-11s%-24s%14d  %14d  %16s  %s', [parts[i].Index, parts[i].Scheme,
      parts[i].TypeHex, parts[i].StartLBA, parts[i].SizeLBA, FormatFloat('0',
      parts[i].SizeLBA * SECTOR_SIZE), parts[i].NameStr]));
  end;
end;

{$ifdef H}
procedure ShowUsage;
begin
  Writeln('Usage:');
  Writeln('  vmdkpart --list <disk.vmdk>');
  Writeln('  vmdkpart --extract <index> --out <file.img> <disk.vmdk>');
  Writeln('  vmdkpart --extract-all --outdir <dir> <disk.vmdk>');
end;

{ ==== Main ==== }

var
  args: array of string;
  i: Integer;
  cmdList, cmdExtract, cmdExtractAll: Boolean;
  outFile, outDir, vmdkPath: string;
  idxStr: string;
  idx: Integer;
  fs: TFileStream;
  reader: TVMDKReader;
  parts: TPartitionArray;
  ok: Boolean;
  p: TPartitionInfo;
  extractedName: string;
begin
  SetLength(args, ParamCount);
  for i := 1 to ParamCount do
    args[i-1] := ParamStr(i);

  cmdList := False;
  cmdExtract := False;
  cmdExtractAll := False;
  outFile := '';
  outDir := '';
  vmdkPath := '';
  idxStr := '';
  idx := -1;

  i := 0;
  while i < Length(args) do
  begin
    if args[i] = '--list' then
    begin
      cmdList := True;
      if i+1 < Length(args) then
      begin
        vmdkPath := args[i+1];
        Inc(i);
      end;
    end
    else if args[i] = '--extract' then
    begin
      cmdExtract := True;
      if i+1 < Length(args) then
      begin
        idxStr := args[i+1];
        Inc(i);
      end;
    end
    else if args[i] = '--out' then
    begin
      if i+1 < Length(args) then
      begin
        outFile := args[i+1];
        Inc(i);
      end;
    end
    else if args[i] = '--extract-all' then
    begin
      cmdExtractAll := True;
    end
    else if args[i] = '--outdir' then
    begin
      if i+1 < Length(args) then
      begin
        outDir := args[i+1];
        Inc(i);
      end;
    end
    else
    begin
      // РѕСЃС‚Р°РЅРЅС–Р№ РЅРµРІС–РґРѕРјРёР№ Р°СЂРіСѓРјРµРЅС‚ С‚СЂР°РєС‚СѓС”РјРѕ СЏРє С€Р»СЏС… РґРѕ VMDK
      vmdkPath := args[i];
    end;
    Inc(i);
  end;

  if (not cmdList) and (not cmdExtract) and (not cmdExtractAll) then
  begin
    ShowUsage;
    Halt(1);
  end;

  if (vmdkPath = '') or (not FileExists(vmdkPath)) then
  begin
    Writeln('Error: VMDK file path missing or not found.');
    Halt(2);
  end;

  fs := TFileStream.Create(vmdkPath, fmOpenRead or fmShareDenyNone);
  reader := nil;
  SetLength(parts, 0);

  try
    reader := TVMDKReader.Create(fs);
    if reader.Kind = vkUnknown then
    begin
      Writeln('Error: Unsupported or corrupt VMDK.');
      Halt(3);
    end;

    Writeln('Detected VMDK kind: ',
      (case reader.Kind of
         vkFlat: 'flat/raw';
         vkSparse: 'monolithicSparse';
       else 'unknown' end));
    Writeln('Capacity: ', reader.CapacitySectors*SECTOR_SIZE, ' bytes (', reader.CapacitySectors, ' sectors)');

    ListPartitions(reader, parts);

    if cmdList then
    begin
      PrintPartitions(parts);
      Halt(0);
    end;

    if cmdExtract then
    begin
      if idxStr = '' then
      begin
        Writeln('Error: --extract requires index.');
        Halt(4);
      end;
      idx := StrToIntDef(idxStr, -1);
      if (idx < 1) or (idx > Length(parts)) then
      begin
        Writeln('Error: invalid partition index.');
        Halt(5);
      end;
      if outFile = '' then
      begin
        outFile := Format('partition_%d.img', [idx]);
      end;
      p := parts[idx-1];
      Writeln(Format('Extracting partition #%d (%s) -> %s',
        [idx, p.Scheme, outFile]));
      ok := ExtractPartition(reader, p, outFile);
      if not ok then
      begin
        Writeln('Extraction failed.');
        Halt(6);
      end;
      Writeln('Done.');
    end
    else if cmdExtractAll then
    begin
      if outDir = '' then outDir := 'parts';
      if not EnsureDirExists(outDir) then
      begin
        Writeln('Error: cannot create outdir: ', outDir);
        Halt(7);
      end;
      for i := 0 to Length(parts)-1 do
      begin
        extractedName := Format('%s%spart_%d_%s.img',
          [IncludeTrailingPathDelimiter(outDir), DirectorySeparator, parts[i].Index, parts[i].Scheme]);
        Writeln(Format('Extracting #%d -> %s', [parts[i].Index, extractedName]));
        ok := ExtractPartition(reader, parts[i], extractedName);
        if not ok then
        begin
          Writeln('Extraction failed for index ', parts[i].Index);
          Halt(8);
        end;
      end;
      Writeln('All partitions extracted.');
    end;

  finally
    if Assigned(reader) then reader.Free;
    fs.Free;
  end;
{$endif}

end.
