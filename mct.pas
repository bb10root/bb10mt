unit MCT;

{$mode ObjFPC}{$H+}
{$modeSwitch advancedRecords}
interface

uses
  Classes, SysUtils;

type
  TMCTHeader = packed record
    Magic: longword;
    Minor: word;
    Major: word;
  end;

  TMCTRange = packed record
    StartBlock: longword;
    EndBlock: longword;
  end;

  TMCTBlockWithFlags = packed record
    Flags: word;
    Range: TMCTRange;
  end;

  TMCTBlockWithDummy = packed record
    Dummy: word;
    Range: TMCTRange;
  end;

  TQNXRegion = packed record
    Dummy: byte;
    ID: byte;
    Range: TMCTRange;
  end;

  TMCTPartition = packed record
    PartitionID: byte;
    Flags: byte;
    Name: array[0..11] of char;
    Range: TMCTRange;
  end;

  TMCTFlashChip = packed record
    Chip: byte;
    Sub: byte;
    Range: TMCTRange;
  end;

  TMCTEntryKind = (
    ekUnknown = $00,
    ekFlashChip = $1D,
    ekBoot0 = $2B,
    ekUser = $31,
    ekBootrom = $18,
    ekMCT = $32,
    ekOSNV = $1E,
    ekCalworking = $37,
    ekOSExt = $3B,
    ekCalBackup = $38,
    ekMBR = $34,
    ekOSFixed = $1B,
    ekRadioFixed = $3A,
    ekFSFixed = $1C,
    ekQNXRegion = $35,
    ekPartition = $39,
    ekNANDConfig = $26,
    ekTag = $23,
    ekCRC = $09,
    ekHVW = $0B,
    ekRAMChip = $1A,
    ekEnd = $FF
    );

  TMCTEntry = record
    Kind: TMCTEntryKind;
    RawData: TBytes;
    function AsFlashChip: TMCTFlashChip;
    function AsPartition: TMCTPartition;
    function AsBlockWithFlags: TMCTBlockWithFlags;
    function AsBlockWithDummy: TMCTBlockWithDummy;
    function AsQNXRegion: TQNXRegion;
  end;

  TMCTParsed = record
    Major: word;
    Minor: word;
    Entries: array of TMCTEntry;
    ActualCRC: cardinal;
    CRC: cardinal;
  end;

function ParseMCTStream(Stream: TStream): TMCTParsed;
procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed; const DestDir: string);
procedure RunExtract(const DumpFile: string; const OutDir: string; offset: int64 = 0);
procedure ParseAndShowMCT(const FileName: string);
procedure ShowParsedMCT(const Parsed: TMCTParsed; actual: boolean = False);
procedure ExtractMCTPartitionToStream(Stream: TStream; const Parsed: TMCTParsed;
  const Name: string; FileStream: TStream);

procedure FreeMCTParsed(var Parsed: TMCTParsed);

implementation

uses crc {$IFNDEF LCL},
  CLI.Console{$ENDIF};       // Optional: Colored console output

const
  MCT_MAGIC = $92BE564A;
  MCT_MAJOR_VERSION = 1;
  BLOCK_SIZE = $10000;
  COPY_CHUNK = $10000;

function GetEntryKind(RawType: byte): TMCTEntryKind; inline;
begin
  case RawType of
    $1D: Result := ekFlashChip;
    $2B: Result := ekBoot0;
    $31: Result := ekUser;
    $18: Result := ekBootrom;
    $32: Result := ekMCT;
    $1E: Result := ekOSNV;
    $37: Result := ekCalWorking;
    $38: Result := ekCalBackup;
    $3B: Result := ekOSExt;
    $34: Result := ekMBR;
    $1B: Result := ekOSFixed;
    $3A: Result := ekRadioFixed;
    $1C: Result := ekFSFixed;
    $35: Result := ekQNXRegion;
    $39: Result := ekPartition;
    $26: Result := ekNANDConfig;
    $23: Result := ekRamChip;
    $09: Result := ekCRC;
    $0B: Result := ekHVW;
    $1A: Result := ekRAMChip;
    $FF: Result := ekEnd;
    else
      Result := ekUnknown;
  end;
end;


function GetEntryDesc(kind: TMCTEntryKind): string; inline;
begin
  case Kind of
    ekFlashChip: Result := 'Flash Chip';
    ekBoot0: Result := 'Boot0 MMC';
    ekUser: Result := 'User MMC';
    ekBootrom: Result := 'Bootrom';
    ekMCT: Result := 'MCT';
    ekOSNV: Result := 'OS NV';
    ekCalWorking: Result := 'Cal Working';
    ekCalBackup: Result := 'Cal Backup';
    ekOSExt: Result := 'OS Extended';
    ekMBR: Result := 'MBR';
    ekOSFixed: Result := 'OS Fixed';
    ekRadioFixed: Result := 'Radio Fixed';
    ekFSFixed: Result := 'FS Fixed';
    ekQNXRegion: Result := 'QNX region';
    ekPartition: Result := 'QNX Partition';
    ekNANDConfig: Result := 'NAND Config';
    ekCRC: Result := 'CRC';
    ekRAMChip: Result := 'RAM Chip';
    ekHVW: Result := 'HWV Entry';
    else
      Result := '';
  end;
end;


function TMCTEntry.AsFlashChip: TMCTFlashChip;
begin
  if Length(RawData) < SizeOf(TMCTFlashChip) then
    raise Exception.Create('Invalid MCTFlashChip size');
  Move(RawData[0], Result, SizeOf(TMCTFlashChip));
end;

function TMCTEntry.AsPartition: TMCTPartition;
begin
  if Length(RawData) <> SizeOf(TMCTPartition) then
    raise Exception.Create('Invalid Partition size');
  Move(RawData[0], Result, SizeOf(TMCTPartition));
end;

function TMCTEntry.AsBlockWithFlags: TMCTBlockWithFlags;
begin
  if Length(RawData) < SizeOf(TMCTBlockWithFlags) then
    raise Exception.Create('Invalid BlockWithFlags size');
  Move(RawData[0], Result, SizeOf(TMCTBlockWithFlags));
end;

function TMCTEntry.AsBlockWithDummy: TMCTBlockWithDummy;
begin
  if Length(RawData) < SizeOf(TMCTBlockWithDummy) then
    raise Exception.Create('Invalid BlockWithDummy size');
  Move(RawData[0], Result, SizeOf(TMCTBlockWithDummy));
end;

function TMCTEntry.AsQNXRegion: TQNXRegion;
begin
  if Length(RawData) < SizeOf(TQNXRegion) then
    raise Exception.Create('Invalid QNXRegion size');
  Move(RawData[0], Result, SizeOf(TQNXRegion));
end;

function ParseMCTStream(Stream: TStream): TMCTParsed;
var
  Hdr: TMCTHeader;
  T, L: byte;
  Buf: TBytes;
  EntryCount, Cap: integer;
  RawMem: TMemoryStream;
  Entry: TMCTEntry;
begin
  if Stream.Size < SizeOf(Hdr) then
    raise Exception.Create('Too small for MCT header');

  Stream.ReadBuffer(Hdr, SizeOf(Hdr));
  if (Hdr.Magic <> MCT_MAGIC) or (Hdr.Major <> MCT_MAJOR_VERSION) then
    raise Exception.Create('Invalid MCT header or unsupported version');

  Result.Major := Hdr.Major;
  Result.Minor := Hdr.Minor;

  RawMem := TMemoryStream.Create;
  try
    RawMem.WriteBuffer(Hdr, SizeOf(Hdr));

    EntryCount := 0;
    Cap := 16;
    SetLength(Result.Entries, Cap);

    while Stream.Position + 2 <= Stream.Size do
    begin
      Stream.ReadBuffer(T, 1);
      Stream.ReadBuffer(L, 1);
      Entry.Kind := GetEntryKind(T);
      if Entry.Kind = ekEnd then Break;

      if (L < 2) or (Stream.Position + (L - 2) > Stream.Size) then
        raise Exception.CreateFmt('Invalid TLV type=%.2x len=%d', [T, L]);

      SetLength(Buf, L - 2);
      if L > 2 then Stream.ReadBuffer(Buf[0], Length(Buf));

      RawMem.WriteBuffer(T, 1);
      RawMem.WriteBuffer(L, 1);
      if L > 2 then RawMem.WriteBuffer(Buf[0], Length(Buf));

      Entry.RawData := Buf;

      if EntryCount = Cap then
      begin
        Cap := Cap + 16;
        SetLength(Result.Entries, Cap);
      end;

      Result.Entries[EntryCount] := Entry;
      Inc(EntryCount);

      if Entry.Kind = ekCRC then
      begin
        if Length(Buf) < 6 then raise Exception.Create('CRC block too short');
        Result.CRC := PLongWord(@Buf[2])^;
        //Result.ActualCRC := CalcCRC32(RawMem.Memory^, RawMem.Size - L);
        Result.ActualCRC := crc32(0, RawMem.Memory, RawMem.Size - L);
      end;

    end;

    SetLength(Result.Entries, EntryCount);
  finally
    RawMem.Free;
  end;
end;

procedure ShowParsedMCT(const Parsed: TMCTParsed; actual: boolean = False);

  function BlocksToStr(Entry: TMCTRange): string;
  begin
    Result := Format('blocks %d-%d', [Entry.StartBlock, Entry.EndBlock]);
  end;

  function BlocksToStrTotal(Entry: TMCTRange): string;
  begin
    Result := Format('blocks %d-%d, total: %d', [Entry.StartBlock, Entry.EndBlock,
      Entry.EndBlock - Entry.StartBlock + 1]);
  end;

var
  i: integer;
  E: TMCTEntry;
  K: TMCTEntryKind;
  s, desc, res: string;
begin
  {$IFNDEF LCL}
  s := '';
  if actual then
    s := ' (actual)';
  TConsole.WriteLn(Format('  Mem Config Table (ver %d.%d)%s:', [Parsed.Major, Parsed.Minor, s]));
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    K := E.Kind;
    desc := GetEntryDesc(K);
    case K of
      ekFlashChip: with E.AsFlashChip do
          res := Format('%s, Chip %d, Sub %d', [BlocksToStr(Range), Chip, Sub]);
      ekBoot0, ekUser: with E.AsBlockWithFlags do
          res := Format('%s, flags = 0x%.4x', [BlocksToStrTotal(Range), Flags]);
      ekBootrom, ekOSExt, ekMBR, ekOSFixed, ekRadioFixed: with E.AsBlockWithDummy do
          res := BlocksToStr(Range);
      ekOSNV, ekCalBackup, ekFSFixed: with E.AsBlockWithDummy do
          res := BlocksToStrTotal(Range);
      ekQNXRegion: with E.AsQNXRegion do
        begin
          res := BlocksToStrTotal(Range);
          desc := desc + ' ' + IntToStr(ID);
        end;
      ekPartition: with E.AsPartition do
          res := Format('type=0x%.2x:%.2x, %s, "%s"', [PartitionID, Flags,
            BlocksToStrTotal(Range), PChar(Name)]);
      ekNANDConfig: with E.AsBlockWithDummy do
          res := Format('type %d, data 0x%.8X 0x%.8X', [Dummy, int64(Range.StartBlock),
            int64(Range.EndBlock)]);
      ekRAMChip: with E.AsBlockWithDummy do
          res := Format('0x%.8X-0x%.8X, Bank Size %d', [Dummy, int64(Range.StartBlock),
            int64(Range.EndBlock), int64(Range.EndBlock - Range.StartBlock + 1)]);
      ekMCT: res := Format('block %d', [PDword(@E.RawData[2])^]);
      ekCRC: res := Format('0x%.8X', [int64(PDword(@E.RawData[2])^)]);
      ekHVW: res := Format('0x%.2X - 0x%.2X', [E.RawData[0], E.RawData[1]]);
    end;
    desc := desc + ':';

    TConsole.WriteLn(Format('    %0:-20s%s', [desc, res]));
  end;
  {$ENDIF}
end;

procedure ParseAndShowMCT(const FileName: string);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(FileName, fmOpenRead);
  try
    Parsed := ParseMCTStream(FS);
    try
      ShowParsedMCT(Parsed);
    finally
      FreeMCTParsed(Parsed);
    end;
  finally
    FS.Free;
  end;
end;

procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed; const DestDir: string);
var
  BaseAddr, NvramOffset: QWord;
  i, Count: integer;
  E: TMCTEntry;
  FileName, BaseName, Key: string;
  FileStream: TFileStream;
  PartOffset, PartSize, PartEnd: QWord;
  StreamMaxOffset, MaxReadable: QWord;
  AvailableSize, Remaining, ChunkSize: QWord;
  Buffer: array of byte;
  FoundNVRAM: boolean;
  NameMap: TStringList;
  partition: TMCTPartition;
begin
  FoundNVRAM := False;

  // 1. Find base address from 'nvram' partition
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if E.Kind = ekPartition then
      partition := E.AsPartition;
    if SameText(Trim(PChar(Partition.Name)), 'nvram') then
    begin
      NvramOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
      BaseAddr := NvramOffset - BLOCK_SIZE;
      FoundNVRAM := True;
      Break;
    end;
  end;

  if not FoundNVRAM then
    raise Exception.Create('Partition "nvram" not found. Cannot determine base address');
  {$IFNDEF LCL}
  Writeln(Format('[i] NVRAM offset = $%.8x → BaseAddr = $%.8x', [NvramOffset, BaseAddr]));
  {$ENDIF}

  StreamMaxOffset := BaseAddr + Stream.Size;
  SetLength(Buffer, COPY_CHUNK);
  NameMap := TStringList.Create;
  NameMap.Sorted := True;
  NameMap.Duplicates := dupIgnore;

  try
    for i := 0 to High(Parsed.Entries) do
    begin
      E := Parsed.Entries[i];
      if E.Kind <> ekPartition then
        continue;
      partition := E.AsPartition;
      PartOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
      PartEnd := QWord(Partition.Range.EndBlock + 1) * BLOCK_SIZE;
      PartSize := PartEnd - PartOffset;

      if PartOffset < BaseAddr then
      begin
        {$IFNDEF LCL}
        Writeln(Format('[!] Partition "%s" is before base address. Skipping.',
          [PChar(Partition.Name)]));
        {$ENDIF}
        continue;
      end;

      MaxReadable := StreamMaxOffset;
      if PartEnd > MaxReadable then
      begin
        AvailableSize := MaxReadable - PartOffset;
        Writeln(Format('[!] Partition "%s" is partially readable: only $%.x bytes available',
          [PChar(Partition.Name), AvailableSize]));
      end
      else
        AvailableSize := PartSize;

      if AvailableSize = 0 then
      begin
        Writeln(Format('[!] Partition "%s" has no readable data. Skipping.',
          [PChar(Partition.Name)]));
        continue;
      end;

      // Унікалізуємо ім’я
      BaseName := Trim(PChar(Partition.Name));
      Key := LowerCase(BaseName);
      Count := NameMap.IndexOf(Key);
      if Count = -1 then
      begin
        NameMap.AddObject(Key, TObject(PtrUInt(1)));
        FileName := Format('%s%2.2x_%s.bin', [IncludeTrailingPathDelimiter(DestDir),
          Partition.PartitionID, BaseName]);
      end
      else
      begin
        Count := PtrUInt(NameMap.Objects[NameMap.IndexOf(Key)]);
        Inc(Count);
        NameMap.Objects[NameMap.IndexOf(Key)] := TObject(PtrUInt(Count));
        FileName := Format('%s%2.2x_%s_%d.bin', [IncludeTrailingPathDelimiter(DestDir),
          Partition.PartitionID, BaseName, Count]);
      end;
      {$IFNDEF LCL}
      Writeln(Format('[+] Saving "%s" → %s (%.x bytes)', [BaseName, FileName, AvailableSize]));
      {$ENDIF}
      Stream.Position := PartOffset - BaseAddr;
      FileStream := TFileStream.Create(FileName, fmCreate);
      try
        Remaining := AvailableSize;
        while Remaining > 0 do
        begin
          ChunkSize := COPY_CHUNK;
          if Remaining < ChunkSize then
            ChunkSize := Remaining;

          Stream.ReadBuffer(Buffer[0], ChunkSize);
          FileStream.WriteBuffer(Buffer[0], ChunkSize);
          Dec(Remaining, ChunkSize);
        end;
      finally
        FileStream.Free;
      end;
    end;
  finally
    NameMap.Free;
    SetLength(Buffer, 0);
  end;
end;


procedure FreeMCTParsed(var Parsed: TMCTParsed);
var
  i: integer;
begin
  for i := 0 to High(Parsed.Entries) do
  begin
    SetLength(Parsed.Entries[i].RawData, 0);
    Parsed.Entries[i].RawData := nil;
  end;
  SetLength(Parsed.Entries, 0);
end;

procedure RunExtract(const DumpFile: string; const OutDir: string; offset: int64 = 0);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(DumpFile, fmOpenRead);
  try
    if FS.Size > offset then
    begin

      FS.Position := offset;
      Parsed := ParseMCTStream(FS);
      try
        ShowParsedMCT(Parsed);
        ExtractMCTPartitionsToFiles(FS, Parsed, OutDir);
      finally
        FreeMCTParsed(Parsed);
      end;
    end
    {$IFNDEF LCL}
    else
      TConsole.WriteLn('Bad MCT offset!', ccRed);
    {$ENDIF}
  finally
    FS.Free;
  end;
end;

procedure ExtractMCTPartitionToStream(Stream: TStream; const Parsed: TMCTParsed;
  const Name: string; FileStream: TStream);
var
  BaseAddr, NvramOffset: QWord;
  i, Count: integer;
  E: TMCTEntry;
  FileName, BaseName, Key: string;
  PartOffset, PartSize, PartEnd: QWord;
  StreamMaxOffset, MaxReadable: QWord;
  AvailableSize, Remaining, ChunkSize: QWord;
  Buffer: array of byte;
  FoundNVRAM: boolean;
  partition: TMCTPartition;
begin
  FoundNVRAM := False;

  // 1. Find base address from 'nvram' partition
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if E.Kind = ekPartition then
      partition := E.AsPartition;
    if SameText(Trim(PChar(Partition.Name)), 'nvram') then
    begin
      NvramOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
      BaseAddr := NvramOffset - BLOCK_SIZE;
      FoundNVRAM := True;
      Break;
    end;
  end;

  if not FoundNVRAM then
    raise Exception.Create('Partition "nvram" not found. Cannot determine base address');

  StreamMaxOffset := BaseAddr + Stream.Size;
  SetLength(Buffer, COPY_CHUNK);

  try
    for i := 0 to High(Parsed.Entries) do
    begin
      E := Parsed.Entries[i];
      if (E.Kind <> ekPartition) then continue;
      partition := E.AsPartition;
      if not SameText(Trim(PChar(Partition.Name)), Name) then continue;

      PartOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
      PartEnd := QWord(Partition.Range.EndBlock + 1) * BLOCK_SIZE;
      PartSize := PartEnd - PartOffset;

      if PartOffset < BaseAddr then
        continue;

      MaxReadable := StreamMaxOffset;
      if PartEnd > MaxReadable then
        AvailableSize := MaxReadable - PartOffset
      else
        AvailableSize := PartSize;

      if AvailableSize = 0 then  continue;

      Stream.Position := PartOffset - BaseAddr;
      FileStream.Size := 0;
      Remaining := AvailableSize;
      while Remaining > 0 do
      begin
        ChunkSize := COPY_CHUNK;
        if Remaining < ChunkSize then
          ChunkSize := Remaining;

        Stream.ReadBuffer(Buffer[0], ChunkSize);
        FileStream.WriteBuffer(Buffer[0], ChunkSize);
        Dec(Remaining, ChunkSize);
      end;
    end;
  finally
    SetLength(Buffer, 0);
  end;
end;


end.
