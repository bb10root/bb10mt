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
procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed; const DestDir: string);
procedure RunExtract(const DumpFile: string; const OutDir: string);
procedure ParseAndShow(const FileName: string);

implementation

uses crc;

function CalcCRC32(const Buf; Len: longword): longword; inline;
begin
  Result := crc32(0, @Buf, Len);
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
  PosBefore: int64;
  CRCFromBlock, CRCActual: longword;
begin
  FillChar(Result, SizeOf(Result), 0);

  if Stream.Size < SizeOf(Hdr) then
    raise Exception.Create('Too small for MCT header');

  Stream.ReadBuffer(Hdr, SizeOf(Hdr));
  if Hdr.Magic <> $92BE564A then
    raise Exception.Create('Invalid MCT magic');
  if Hdr.Major <> 1 then
    raise Exception.Create('Unsupported MCT version');

  RawMem := TMemoryStream.Create;
  try
    RawMem.WriteBuffer(Hdr, SizeOf(Hdr));

    while Stream.Position + 2 <= Stream.Size do
    begin
      PosBefore := Stream.Position;
      Stream.ReadBuffer(T, 1);
      Stream.ReadBuffer(L, 1);

      if (L < 2) or (Stream.Position + (L - 2) > Stream.Size) then
        raise Exception.CreateFmt('Invalid TLV type=%.2x len=%d', [T, L]);

      SetLength(Buf, L - 2);
      Stream.ReadBuffer(Buf[0], Length(Buf));

      RawMem.WriteBuffer(T, 1);
      RawMem.WriteBuffer(L, 1);
      RawMem.WriteBuffer(Buf[0], Length(Buf));

      FillChar(Entry, SizeOf(Entry), 0);
      Entry.RawType := T;
      Entry.RawData := Copy(Buf);

      case T of
        $39:
          if Length(Buf) = SizeOf(TMCTPartition) then
            Move(Buf[0], Entry.Partition, SizeOf(TMCTPartition));
        $26:
          if Length(Buf) >= SizeOf(TMCTConfig26) then
            Move(Buf[0], Entry.Config, SizeOf(TMCTConfig26));
      end;

      SetLength(Result.Entries, Length(Result.Entries) + 1);
      Result.Entries[High(Result.Entries)] := Entry;

      if T = $09 then
      begin
        if Length(Buf) < 6 then
          raise Exception.Create('CRC block too short');

        CRCFromBlock := PLongWord(@Buf[2])^;
        CRCActual := CalcCRC32(RawMem.Memory^, RawMem.Size - L);

        if CRCActual = CRCFromBlock then
          Writeln(Format('[CRC] OK: %.8x', [CRCActual]))
        else
          Writeln(Format('[CRC] MISMATCH! Got=%.8x  Expected=%.8x', [CRCFromBlock, CRCActual]));
      end;

      if T = $FF then
        Break;
    end;
  finally
    RawMem.Free;
  end;
end;


procedure ShowParsed(const Parsed: TMCTParsed);
var
  i: integer;
  E: TMCTEntry;
  K: TMCTEntryKind;
begin
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    K := GetEntryKind(E.RawType);

    case K of
      ekPartition:
        Writeln(Format('[%d] Partition "%s" Offset=$%.8x Size=$%.8x Type=$%.2x',
          [i, PChar(@E.Partition.Name), E.Partition.StartBlock shl 16,
          ((E.Partition.EndBlock + 1) shl 16) - (E.Partition.StartBlock shl 16),
          E.Partition.PartitionID]));
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
        Writeln(Format('[%d] Unknown type=%.2x, Len=%d', [i, E.RawType, Length(E.RawData)]));
    end;
  end;
end;


procedure ParseAndShow(const FileName: string);
var
  FS: TFileStream;
  Parsed: TMCTParsed;
begin
  FS := TFileStream.Create(FileName, fmOpenRead);
  try
    Parsed := ParseMCTStream(FS);
    ShowParsed(Parsed);
  finally
    FS.Free;
  end;
end;

procedure ExtractMCTPartitionsToFiles(Stream: TStream; const Parsed: TMCTParsed; const DestDir: string);
const
  BLOCK_SIZE = $10000;
var
  BaseAddr, NvramOffset: QWord;
  i: integer;
  E: TMCTEntry;
  FileName: string;
  FileStream: TFileStream;
  PartOffset, PartSize: QWord;
  Buf: array of byte;
  FoundNVRAM: boolean;
begin
  FoundNVRAM := False;

  // 1. Знаходимо nvram
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if GetEntryKind(E.RawType) = ekPartition then
      if SameText(Trim(PChar(@E.Partition.Name)), 'nvram') then
      begin
        NvramOffset := QWord(E.Partition.StartBlock) * BLOCK_SIZE;
        BaseAddr := NvramOffset - BLOCK_SIZE;
        FoundNVRAM := True;
        Break;
      end;
  end;

  if not FoundNVRAM then
    raise Exception.Create('Partition "nvram" not found. Cannot determine base address');

  Writeln(Format('[i] NVRAM offset = $%.8x → BaseAddr = $%.8x', [NvramOffset, BaseAddr]));

  // 2. Зберігаємо всі розділи
  for i := 0 to High(Parsed.Entries) do
  begin
    E := Parsed.Entries[i];
    if GetEntryKind(E.RawType) <> ekPartition then
      continue;

    PartOffset := QWord(E.Partition.StartBlock) * BLOCK_SIZE;
    PartSize := (QWord(E.Partition.EndBlock + 1) * BLOCK_SIZE) - PartOffset;

    if PartOffset < BaseAddr then
    begin
      Writeln(Format('[!] Partition "%s" before base address. Skipping.',
        [PChar(@E.Partition.Name)]));
      continue;
    end;

    FileName := Format('%s/%2.2x_%s.bin', [IncludeTrailingPathDelimiter(DestDir),
      E.Partition.PartitionID, Trim(PChar(@E.Partition.Name))]);

    Writeln(Format('[+] Writing partition "%s" to "%s" Offset=$%.8x Size=%.x',
      [PChar(@E.Partition.Name), FileName, PartOffset, PartSize]));

    SetLength(Buf, PartSize);
    Stream.Position := PartOffset - BaseAddr;
    Stream.ReadBuffer(Buf[0], PartSize);

    FileStream := TFileStream.Create(FileName, fmCreate);
    try
      FileStream.WriteBuffer(Buf[0], Length(Buf));
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
  FS := TFileStream.Create(DumpFile, fmOpenRead);
  try
    Parsed := ParseMCTStream(FS);
    ShowParsed(Parsed); // необов'язково
    ExtractMCTPartitionsToFiles(FS, Parsed, OutDir);
  finally
    FS.Free;
  end;
end;


end.
