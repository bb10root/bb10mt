unit uMCT;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

type
  TMCTHeader = packed record
    Magic: longword;
    Minor: word;
    Major: word;
  end;

  TMCTPartition = packed record
    PartitionID: byte;
    Flags: byte;
    Name: array[0..11] of char;
    StartBlock: longword;
    EndBlock: longword;
  end;

  TMCTConfig26 = packed record
    ParamCode: word;
    ParamValue: word;
    Flags: longword;
    Reserved: array[0..3] of byte;
  end;

  TMCTEntryKind = (
    ekUnknown = $00,
    ekPartition = $39,
    ekConfig = $26,
    ekTag = $23,
    ekCRC = $09,
    ekEnd = $FF
    );

  TMCTEntry = record
    RawType: byte;
    RawData: TBytes;
    case byte of
      0: (Partition: TMCTPartition);
      1: (Config: TMCTConfig26);
  end;

  TMCTParsed = record
    Entries: array of TMCTEntry;
  end;

function ParseMCTStream(Stream: TStream): TMCTParsed;
procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed;
  const DestDir: string);
procedure RunExtract(const DumpFile: string; const OutDir: string);
procedure ParseAndShow(const FileName: string);
procedure ShowParsedMCT(const Parsed: TMCTParsed; Verbose: boolean = False);
function GetPartitionName(const NameArr: array of char): string;

implementation

uses crc;

function CalcCRC32(const Buf; Len: longword): longword; inline;
begin
  Result := crc32(0, @Buf, Len);
end;

function GetPartitionName(const NameArr: array of char): string;
var
  Len: integer;
begin
  Len := 0;
  while (Len < Length(NameArr)) and (NameArr[Len] <> #0) do
    Inc(Len);
  SetString(Result, PChar(@NameArr[0]), Len);
  Result := Trim(Result);
end;

function GetEntryKind(RawType: byte): TMCTEntryKind;
begin
  case RawType of
    $39: Exit(ekPartition);
    $26: Exit(ekConfig);
    $23: Exit(ekTag);
    $09: Exit(ekCRC);
    $FF: Exit(ekEnd);
    else
      Exit(ekUnknown);
  end;
end;

function ParseMCTStream(Stream: TStream): TMCTParsed;
var
  Hdr: TMCTHeader;
  T, L: byte;
  Buf: TBytes;
  Entry: TMCTEntry;
  RawMem: TMemoryStream;
  CRCFromBlock, CRCActual: longword;
  Capacity, Count: integer;
  CRCPosInRawMem: int64;
begin
  FillChar(Result, SizeOf(Result), 0);

  if Stream.Size < SizeOf(Hdr) then
    raise Exception.Create('Too small for MCT header');

  Stream.ReadBuffer(Hdr, SizeOf(Hdr));
  if Hdr.Magic <> $92BE564A then
    raise Exception.Create('Invalid MCT magic');
  if Hdr.Major <> 1 then
    raise Exception.Create('Unsupported MCT version');

  Capacity := 16;
  Count := 0;
  SetLength(Result.Entries, Capacity);

  RawMem := TMemoryStream.Create;
  try
    RawMem.WriteBuffer(Hdr, SizeOf(Hdr));

    while Stream.Position + 2 <= Stream.Size do
    begin
      Stream.ReadBuffer(T, 1);
      Stream.ReadBuffer(L, 1);

      if (L < 2) or (Stream.Position + (L - 2) > Stream.Size) then
        raise Exception.CreateFmt('Invalid TLV type=%.2x len=%d', [T, L]);

      SetLength(Buf, L - 2);
      if Length(Buf) > 0 then
        Stream.ReadBuffer(Buf[0], Length(Buf));

      CRCPosInRawMem := RawMem.Position;
      // Запам'ятовуємо позицію до запису поточного TLV

      RawMem.WriteBuffer(T, 1);
      RawMem.WriteBuffer(L, 1);
      if Length(Buf) > 0 then
        RawMem.WriteBuffer(Buf[0], Length(Buf));

      FillChar(Entry, SizeOf(Entry), 0);
      Entry.RawType := T;
      Entry.RawData := Copy(Buf);

      case T of
        $39:
          if Length(Buf) >= SizeOf(TMCTPartition) then
            Move(Buf[0], Entry.Partition, SizeOf(TMCTPartition));
        $26:
          if Length(Buf) >= SizeOf(TMCTConfig26) then
            Move(Buf[0], Entry.Config, SizeOf(TMCTConfig26));
      end;

      if Count >= Capacity then
      begin
        Capacity := Capacity * 2;
        SetLength(Result.Entries, Capacity);
      end;

      Result.Entries[Count] := Entry;
      Inc(Count);

      if T = $09 then
      begin
        if Length(Buf) < 4 then
          raise Exception.Create('CRC block too short');

        CRCFromBlock := PLongWord(@Buf[0])^;
        // Залежно від структури блоку (зазвичай offset 0 або 2)
        CRCActual := CalcCRC32(RawMem.Memory^, CRCPosInRawMem);

        if CRCActual = CRCFromBlock then
          Writeln(Format('[CRC] OK: %.8x', [CRCActual]))
        else
          Writeln(Format('[CRC] MISMATCH! Got=%.8x Expected=%.8x',
            [CRCFromBlock, CRCActual]));
      end;

      if T = $FF then
        Break;
    end;
  finally
    RawMem.Free;
  end;

  SetLength(Result.Entries, Count);
end;

procedure ShowParsedMCT(const Parsed: TMCTParsed; Verbose: boolean = False);
var
  i: integer;
  E: TMCTEntry;
  K: TMCTEntryKind;
  PartName: string;
begin
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    K := GetEntryKind(E.RawType);

    case K of
      ekPartition:
      begin
        PartName := GetPartitionName(E.Partition.Name);
        Writeln(Format('[%d] Partition "%s" Offset=$%.8x Size=$%.8x Type=$%.2x',
          [i, PartName, E.Partition.StartBlock shl 16,
          ((E.Partition.EndBlock + 1) shl 16) - (E.Partition.StartBlock shl 16),
          E.Partition.PartitionID]));
      end;
      ekConfig:
        Writeln(Format('[%d] Config Param=%.4x Value=%.4x Flags=%.8x',
          [i, E.Config.ParamCode, E.Config.ParamValue, E.Config.Flags]));
      ekCRC:
        Writeln(Format('[%d] CRC32 block (raw %d bytes)', [i, Length(E.RawData)]));
      ekEnd:
        Writeln(Format('[%d] End of MCT', [i]));
      ekTag:
        Writeln(Format('[%d] Tag block, Len=%d', [i, Length(E.RawData)]));
      ekUnknown:
        Writeln(Format('[%d] Unknown type=%.2x, Len=%d',
          [i, E.RawType, Length(E.RawData)]));
    end;
  end;
end;

procedure ParseAndShow(const FileName: string);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Parsed := ParseMCTStream(FS);
    ShowParsedMCT(Parsed);
  finally
    FS.Free;
  end;
end;

procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed;
  const DestDir: string);
const
  BLOCK_SIZE = $10000;
  CHUNK_SIZE = $100000; // 1MB buffer for fast stream copying
var
  BaseAddr, NvramOffset: QWord;
  i: integer;
  E: TMCTEntry;
  FileName, PartName: string;
  FileStream: TFileStream;
  PartOffset, PartSize, BytesToRead, BytesRead: QWord;
  Buf: array[0..CHUNK_SIZE - 1] of byte;
  FoundNVRAM: boolean;
begin
  FoundNVRAM := False;
  NvramOffset := 0;

  // 1. Знаходимо nvram для обчислення базового зміщення
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if GetEntryKind(E.RawType) = ekPartition then
    begin
      PartName := GetPartitionName(E.Partition.Name);
      if SameText(PartName, 'nvram') then
      begin
        NvramOffset := QWord(E.Partition.StartBlock) * BLOCK_SIZE;
        BaseAddr := NvramOffset - BLOCK_SIZE;
        FoundNVRAM := True;
        Break;
      end;
    end;
  end;

  if not FoundNVRAM then
    raise Exception.Create('Partition "nvram" not found. Cannot determine base address');

  Writeln(Format('[i] NVRAM offset = $%.8x -> BaseAddr = $%.8x',
    [NvramOffset, BaseAddr]));

  // 2. Зберігаємо всі розділи блоковим копіюванням
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if GetEntryKind(E.RawType) <> ekPartition then
      continue;

    PartName := GetPartitionName(E.Partition.Name);
    PartOffset := QWord(E.Partition.StartBlock) * BLOCK_SIZE;
    PartSize := (QWord(E.Partition.EndBlock + 1) * BLOCK_SIZE) - PartOffset;

    if PartOffset < BaseAddr then
    begin
      Writeln(Format('[!] Partition "%s" before base address. Skipping.', [PartName]));
      continue;
    end;

    FileName := Format('%s/%2.2x_%s.bin',
      [IncludeTrailingPathDelimiter(DestDir), E.Partition.PartitionID, PartName]);

    Writeln(Format('[+] Writing partition "%s" to "%s" Offset=$%.8x Size=$%.8x',
      [PartName, FileName, PartOffset, PartSize]));

    Stream.Position := PartOffset - BaseAddr;
    FileStream := TFileStream.Create(FileName, fmCreate);
    try
      BytesToRead := PartSize;
      while BytesToRead > 0 do
      begin
        if BytesToRead > CHUNK_SIZE then
          BytesRead := CHUNK_SIZE
        else
          BytesRead := BytesToRead;

        Stream.ReadBuffer(Buf[0], BytesRead);
        FileStream.WriteBuffer(Buf[0], BytesRead);
        Dec(BytesToRead, BytesRead);
      end;
    finally
      FileStream.Free;
    end;
  end;
end;

procedure RunExtract(const DumpFile: string; const OutDir: string);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(DumpFile, fmOpenRead or fmShareDenyNone);
  try
    Parsed := ParseMCTStream(FS);
    ShowParsedMCT(Parsed);
    ExtractMCTPartitionsToFiles(FS, Parsed, OutDir);
  finally
    FS.Free;
  end;
end;

end.
