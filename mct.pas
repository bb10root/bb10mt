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
    ekCalWorking = $37,
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
procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed;
  const DestDir: string);
procedure RunExtract(const DumpFile: string; const OutDir: string; Offset: int64 = 0);
procedure ParseAndShowMCT(const FileName: string);
procedure ShowParsedMCT(const Parsed: TMCTParsed; Actual: boolean = False);
procedure ExtractMCTPartitionToStream(Stream: TStream; const Parsed: TMCTParsed;
  const Name: string; FileStream: TStream);

procedure FreeMCTParsed(var Parsed: TMCTParsed);

implementation

uses
  crc
  {$IFNDEF LCL}
  , CLI.Console
  {$ENDIF};

const
  MCT_MAGIC = $92BE564A;
  MCT_MAJOR_VERSION = 1;
  BLOCK_SIZE = $10000;
  COPY_CHUNK = $10000;

// Безпечне отримання назви партиції з нетермінованого 12-байтового масиву
function GetPartitionName(const Part: TMCTPartition): string;
var
  Buffer: array[0..12] of char;
begin
  FillChar(Buffer, SizeOf(Buffer), 0);
  Move(Part.Name[0], Buffer[0], SizeOf(Part.Name));
  Result := Trim(StrPas(Buffer));
end;

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
    $23: Result := ekTag;
    $09: Result := ekCRC;
    $0B: Result := ekHVW;
    $1A: Result := ekRAMChip;
    $FF: Result := ekEnd;
    else
      Result := ekUnknown;
  end;
end;

function GetEntryDesc(Kind: TMCTEntryKind): string; inline;
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
    ekTag: Result := 'Tag Entry';
    else
      Result := 'Unknown';
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
  if Length(RawData) < SizeOf(TMCTPartition) then
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
  FillChar(Result, SizeOf(Result), 0);

  if (Stream.Size - Stream.Position) < SizeOf(Hdr) then
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

    while (Stream.Position + 2) <= Stream.Size do
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

      if EntryCount >= Cap then
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
        Result.ActualCRC := crc32(0, RawMem.Memory, RawMem.Size - L);
      end;
    end;

    SetLength(Result.Entries, EntryCount);
  finally
    RawMem.Free;
  end;
end;

procedure ShowParsedMCT(const Parsed: TMCTParsed; Actual: boolean = False);

  function BlocksToStr(const Entry: TMCTRange): string;
  begin
    Result := Format('blocks %d-%d', [Entry.StartBlock, Entry.EndBlock]);
  end;

  function BlocksToStrTotal(const Entry: TMCTRange): string;
  begin
    Result := Format('blocks %d-%d, total: %d', [Entry.StartBlock,
      Entry.EndBlock, Entry.EndBlock - Entry.StartBlock + 1]);
  end;

var
  i: integer;
  E: TMCTEntry;
  K: TMCTEntryKind;
  S, Desc, Res: string;
begin
  {$IFNDEF LCL}
  S := '';
  if Actual then S := ' (actual)';
  TConsole.WriteLn(Format('  Mem Config Table (ver %d.%d)%s:',
    [Parsed.Major, Parsed.Minor, S]));

  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    K := E.Kind;
    Desc := GetEntryDesc(K);
    Res := '';

    case K of
      ekFlashChip:
        with E.AsFlashChip do
          Res := Format('%s, Chip %d, Sub %d', [BlocksToStr(Range), Chip, Sub]);
      ekBoot0, ekUser:
        with E.AsBlockWithFlags do
          Res := Format('%s, flags = 0x%.4x', [BlocksToStrTotal(Range), Flags]);
      ekBootrom, ekOSExt, ekMBR, ekOSFixed, ekRadioFixed:
        with E.AsBlockWithDummy do
          Res := BlocksToStr(Range);
      ekOSNV, ekCalBackup, ekFSFixed:
        with E.AsBlockWithDummy do
          Res := BlocksToStrTotal(Range);
      ekQNXRegion:
        with E.AsQNXRegion do
        begin
          Res := BlocksToStrTotal(Range);
          Desc := Desc + ' ' + IntToStr(ID);
        end;
      ekPartition:
        with E.AsPartition do
          Res := Format('type=0x%.2x:%.2x, %s, "%s"',
            [PartitionID, Flags, BlocksToStrTotal(Range),
            GetPartitionName(E.AsPartition)]);
      ekNANDConfig:
        with E.AsBlockWithDummy do
          Res := Format('type %d, data 0x%.8X 0x%.8X',
            [Dummy, int64(Range.StartBlock), int64(Range.EndBlock)]);
      ekRAMChip:
        with E.AsBlockWithDummy do
          Res := Format('0x%.8X-0x%.8X, Bank Size %d',
            [Dummy, int64(Range.StartBlock), int64(Range.EndBlock),
            int64(Range.EndBlock - Range.StartBlock + 1)]);
      ekMCT:
        if Length(E.RawData) >= 6 then
          Res := Format('block %d', [PDWord(@E.RawData[2])^]);
      ekCRC:
        if Length(E.RawData) >= 6 then
          Res := Format('0x%.8X', [int64(PDWord(@E.RawData[2])^)]);
      ekHVW:
        if Length(E.RawData) >= 2 then
          Res := Format('0x%.2X - 0x%.2X', [E.RawData[0], E.RawData[1]]);
    end;

    Desc := Desc + ':';
    TConsole.WriteLn(Format('    %-20s%s', [Desc, Res]));
  end;
  {$ENDIF}
end;

procedure ParseAndShowMCT(const FileName: string);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
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

procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed;
  const DestDir: string);
var
  BaseAddr, NvramOffset: QWord;
  i, CountIdx, CountVal: integer;
  E: TMCTEntry;
  FileName, BaseName, Key: string;
  FileStream: TFileStream;
  PartOffset, PartSize, PartEnd: QWord;
  StreamMaxOffset, MaxReadable, AvailableSize, Remaining, ChunkSize: QWord;
  Buffer: TBytes;
  FoundNVRAM: boolean;
  NameMap: TStringList;
  Partition: TMCTPartition;
begin
  FoundNVRAM := False;
  BaseAddr := 0;

  // 1. Пошук базової адреси за партицією 'nvram'
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if E.Kind = ekPartition then
    begin
      Partition := E.AsPartition;
      if SameText(GetPartitionName(Partition), 'nvram') then
      begin
        NvramOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
        BaseAddr := NvramOffset - BLOCK_SIZE;
        FoundNVRAM := True;
        Break;
      end;
    end;
  end;

  if not FoundNVRAM then
    raise Exception.Create('Partition "nvram" not found. Cannot determine base address');

  {$IFNDEF LCL}
  WriteLn(Format('[i] NVRAM offset = $%.8x -> BaseAddr = $%.8x',
    [NvramOffset, BaseAddr]));
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
      if E.Kind <> ekPartition then Continue;

      Partition := E.AsPartition;
      PartOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
      PartEnd := QWord(Partition.Range.EndBlock + 1) * BLOCK_SIZE;
      PartSize := PartEnd - PartOffset;

      if PartOffset < BaseAddr then
      begin
        {$IFNDEF LCL}
        WriteLn(Format('[!] Partition "%s" is before base address. Skipping.',
          [GetPartitionName(Partition)]));
        {$ENDIF}
        Continue;
      end;

      MaxReadable := StreamMaxOffset;
      if PartEnd > MaxReadable then
      begin
        AvailableSize := MaxReadable - PartOffset;
        {$IFNDEF LCL}
        WriteLn(Format(
          '[!] Partition "%s" is partially readable: only $%.x bytes available',
          [GetPartitionName(Partition), AvailableSize]));
        {$ENDIF}
      end
      else
        AvailableSize := PartSize;

      if AvailableSize = 0 then Continue;

      // Генеруємо унікальну назву файлу
      BaseName := GetPartitionName(Partition);
      Key := LowerCase(BaseName);
      CountIdx := NameMap.IndexOf(Key);

      if CountIdx = -1 then
      begin
        NameMap.AddObject(Key, TObject(PtrUInt(1)));
        FileName := Format('%s%2.2x_%s.bin',
          [IncludeTrailingPathDelimiter(DestDir), Partition.PartitionID, BaseName]);
      end
      else
      begin
        CountVal := PtrUInt(NameMap.Objects[CountIdx]) + 1;
        NameMap.Objects[CountIdx] := TObject(PtrUInt(CountVal));
        FileName := Format('%s%2.2x_%s_%d.bin',
          [IncludeTrailingPathDelimiter(DestDir), Partition.PartitionID,
          BaseName, CountVal]);
      end;

      {$IFNDEF LCL}
      WriteLn(Format('[+] Saving "%s" -> %s (%.x bytes)',
        [BaseName, FileName, AvailableSize]));
      {$ENDIF}

      Stream.Position := PartOffset - BaseAddr;
      FileStream := TFileStream.Create(FileName, fmCreate);
      try
        Remaining := AvailableSize;
        while Remaining > 0 do
        begin
          ChunkSize := COPY_CHUNK;
          if Remaining < ChunkSize then ChunkSize := Remaining;

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
    SetLength(Parsed.Entries[i].RawData, 0);
  SetLength(Parsed.Entries, 0);
end;

procedure RunExtract(const DumpFile: string; const OutDir: string; Offset: int64 = 0);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(DumpFile, fmOpenRead or fmShareDenyWrite);
  try
    if FS.Size > Offset then
    begin
      FS.Position := Offset;
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
    {$ELSE}
    ;
    {$ENDIF}
  finally
    FS.Free;
  end;
end;

procedure ExtractMCTPartitionToStream(Stream: TStream; const Parsed: TMCTParsed;
  const Name: string; FileStream: TStream);
var
  BaseAddr, NvramOffset: QWord;
  i: integer;
  E: TMCTEntry;
  PartOffset, PartSize, PartEnd: QWord;
  StreamMaxOffset, AvailableSize, Remaining, ChunkSize: QWord;
  Buffer: TBytes;
  FoundNVRAM: boolean;
  Partition: TMCTPartition;
begin
  FoundNVRAM := False;
  BaseAddr := 0;

  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if E.Kind = ekPartition then
    begin
      Partition := E.AsPartition;
      if SameText(GetPartitionName(Partition), 'nvram') then
      begin
        NvramOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
        BaseAddr := NvramOffset - BLOCK_SIZE;
        FoundNVRAM := True;
        Break;
      end;
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
      if E.Kind <> ekPartition then Continue;

      Partition := E.AsPartition;
      if not SameText(GetPartitionName(Partition), Name) then Continue;

      PartOffset := QWord(Partition.Range.StartBlock) * BLOCK_SIZE;
      PartEnd := QWord(Partition.Range.EndBlock + 1) * BLOCK_SIZE;
      PartSize := PartEnd - PartOffset;

      if PartOffset < BaseAddr then Continue;

      if PartEnd > StreamMaxOffset then
        AvailableSize := StreamMaxOffset - PartOffset
      else
        AvailableSize := PartSize;

      if AvailableSize = 0 then Continue;

      Stream.Position := PartOffset - BaseAddr;
      FileStream.Size := 0;
      Remaining := AvailableSize;

      while Remaining > 0 do
      begin
        ChunkSize := COPY_CHUNK;
        if Remaining < ChunkSize then ChunkSize := Remaining;

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
